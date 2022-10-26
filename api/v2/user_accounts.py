import logging

import json
import requests
import connexion
import datetime
import os

from kubernetes.client import ApiException, ApiValueError
from werkzeug.exceptions import Unauthorized
from jose import JWTError, jwt, jws
import six

from bson import ObjectId

import pkg.kube

from pkg import config, kube
from pkg.auth import keycloak
from pkg.config import backend_config

#from helper import etcdClient
#from pkg import validate

logger = logging.getLogger('user_accounts')

# TODO: v2
USER_ACCOUNTS_COLLECTION_NAME = 'user_accounts'


def ensure_namespace_exists(username, labels):
    namespace_name = pkg.kube.get_resource_namespace(username)
    # resource_prefix = config.get_resource_name(username)

    try:
        return kube.create_namespace(namespace_name, labels=labels)
    except ApiException as err:
        # Ignore if already exists
        if err.status != 409:
            logger.error("ApiException: Failed to create user namespace (%s): %s" % (namespace_name, err))
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to create user namespace (%s): %s" % (namespace_name, err))


def ensure_resource_quota_exists(username, labels):
    namespace_name = pkg.kube.get_resource_namespace(username)

    # Always create resource quote
    try:
        quota_name = pkg.kube.get_resource_name(username, "medium")
        return kube.create_resource_quota(quota_name=quota_name,
                                           namespace=namespace_name,
                                           labels=labels,
                                           hard_quotas={
            # Limit container resources
            'requests.storage': '10Gi',
            'requests.cpu': '2',
            'requests.memory': '4Gi',

            # Limit to 12 possible connections
            'count/services': 12,

            # Limit to 10 inactive apps
            'count/deployments.apps': 10,

            # Limit to 5 active pods
            'count/pods': 5,

            # NOTE: Loadbalancers are not supported at this time
            'count/services.loadbalancers': 0
        })
    except ApiException as err:
        # Ignore if already exists
        if err.status != 409:
            logger.error("ApiException: Failed to create user resource quotas: " + str(err))
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to create user resource quotas: " + str(err))


def ensure_userdata_configmap_exists(username, labels):
    configmap_namespace = pkg.kube.get_resource_namespace(username)
    configmap_name = pkg.kube.get_resource_name(username, "user-data")

    init_user_data = {"apps": [], "specs": []}

    # Ensure empty account resources have been created
    try:
        return kube.create_configmap(
            configmap_name=configmap_name,
            namespace=configmap_namespace,
            labels=labels,

            # "config.json": '{"command":"/usr/bin/mysqld_safe"}',
            # "frontend.cnf": "[mysqld]\nbind-address = 10.0.0.3\n",
            configmap_data={
                "userdata.json": json.dumps(init_user_data),
            })
    except ApiException as err:
        # Ignore if already exists
        if err.status != 409:
            logger.error("ApiException: Failed to create userdata configmap: " + str(err))
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to create userdata configmap: " + str(err))


def ensure_home_data_pvc_exists(username, labels):
    pvc_namespace = pkg.kube.get_resource_namespace(username)
    pvc_suffix = backend_config['userapps']['home'] if 'userapps' in backend_config and 'home' in backend_config['userapps'] else 'home-data'
    pvc_name = pkg.kube.get_resource_name(username, pvc_suffix)

    logger.debug("Creating PVC: " + pvc_name)

    try:
        return kube.create_persistent_volume_claim(
            pvc_name=pvc_name,
            namespace=pvc_namespace,
            storage_class=config.KUBE_PVC_STORAGECLASS,
        )
    except ApiException as err:
        # Ignore if already exists
        if err.status != 409:
            logger.error("ApiException: Failed to create userdata configmap: " + str(err))
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to create userdata configmap: " + str(err))


def ensure_user_ready(username):
    # Apply a set of identifiers to trace back to this specific Workbench instance
    labels = {
        'manager': 'workbench',
        'user': username
    }

    namespace_name = pkg.kube.get_resource_namespace(username)

    if namespace_name == username:
        ensure_namespace_exists(username, labels=labels)

    ensure_resource_quota_exists(username, labels=labels)
    #ensure_userdata_configmap_exists(username, labels=labels)
    ensure_home_data_pvc_exists(username, labels=labels)
    # TODO: Create NetworkPolicy?


# A wrapper for the following:
#   curl http://keycloak/auth/realms/<my_realm>/protocol/openid-connect/token -XPOST --header 'Content-Type: application/x-www-form-urlencoded'
#      --data-urlencode 'client_id=workbench-local' \
#      --data-urlencode 'grant_type=password' \
#      --data-urlencode 'username=test' \
#      --data-urlencode 'password=mysamplepasswordissupersecure' \
#      --data-urlencode 'scope=openid' \
#      --data-urlencode 'client_secret=73305daa-c3d9-4ec7-aec0-caa9b030e182'
def post_authenticate(auth):
    # user params
    username = auth['username']
    password = auth['password']

    # Send auth request to Keycloak
    try:
        tokens = keycloak.login(username, password)

        # Ensure account resources have been created
        ensure_user_ready(username)

        return 200, { 'set-cookie': 'tokens=' + keycloak.encode_tokens(tokens)}
    except requests.exceptions.RequestException as e:
        logger.error("Failed to login to Keycloak: %s" % e)
        return { 'error': 'Invalid credentials' }, 401


# A wrapper for the following:
#   curl -XPOST http://keycloak/auth/realms/<my_realm>/protocol/openid-connect/logout
#      --data-urlencode 'client_secret=73305daa-c3d9-4ec7-aec0-caa9b030e182' \
#      --data-urlencode 'client_id=workbench-local' \
#      --data-urlencode 'refresh_token=<refresh_token>'
def delete_authenticate():
    if 'tokens' not in connexion.request.cookies:
        return { 'error': 'No tokens cookie was provided' }, 400

    # Send logout request to Keycloak
    try:
        keycloak.logout()

        return 204, {
            'set-cookie': "tokens=; expires=Thu, 01 Jan 1970 00:00:00 GMT",
        }
    except requests.exceptions.RequestException as e:
        logger.error("Failed to logout of Keycloak: %s" % e)
        return { 'error': 'Failed to logout: %s' % e }, 500


def get_account_by_id(user, token_info, account_id):
    if account_id is None or account_id == '':
        return { 'error': 'Account ID (username / namespace) is required' }, 400

    try:
        userinfo = keycloak.get_user_info()

        return userinfo, 202
    except requests.exceptions.RequestException as e:
        logger.error("Failed to fetch userinfo from Keycloak: %s" % e)
        return { 'error': 'Failed to fetch userinfo from Keycloak: %s' % e }, 500



