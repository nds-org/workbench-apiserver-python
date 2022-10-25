import json

import requests
from werkzeug.exceptions import Unauthorized

from pkg import config
import logging

logger = logging.getLogger("pkg.auth.keycloak")

#
# Expected UserInfo format:
#
# {
#   "email": "test@localhost",
#   "groups": [
#     "/workbench-users",                   # Groups
#     "role:workbench-user",                # Realm Roles
#     "role:workbench-local:client-role"    # Client Roles
#   ],
#   "sub": "test"
# }
# TODO: x-tokenInfoUrl can't handle insecure SSL
def userinfo(access_token) -> dict:
    logger.info("Verifying Keycloak token: " + access_token)
    try:
        resp = requests.get(
            url=config.KC_USERINFO_URL,
            data={'scope': config.KC_SCOPE},
            verify=config.SSL_VERIFY,
            headers={"Authorization": f'Bearer {access_token}'}
        )
        resp.raise_for_status()
        user = resp.json()

        groups = []

        # Real groups start with / and can be hierarchical
        if 'groups' in user:
            for grp in user['groups']:
                groups.append(grp)

        # Next are Realm Roles, which start with `role:`
        if 'realm_access' in user and 'roles' in user['realm_access']:
            for role in user['realm_access']['roles']:
                groups.append(f"role:{role}")

        # Finally add Client Roles, which start with `role:{client_name}`
        if 'resource_access' in user:
            for client_name in user['resource_access']:
                if 'roles' not in user['resource_access'][client_name]:
                    continue
                for role in user['resource_access'][client_name]['roles']:
                    groups.append(f"role:{client_name}:{role}")

        # TODO: oauth2-proxy does not support arbitrary claims yet, so excluding name for consistency
        # See https://github.com/oauth2-proxy/oauth2-proxy/issues/834
        return {
            'email': user['email'],
            'groups': groups,
            # 'family_name': user['family_name'],
            # 'given_name': user['given_name'],
            'sub': user['preferred_username'].replace('@', '').replace('.', '')
        }
    except Exception as e:
        logger.warning("Keycloak token verification failed: " + str(e))
        pass


def login(username, password):
    try:
        resp = requests.post(url=config.KC_TOKEN_URL, verify=config.SSL_VERIFY, data={
            'username': username,
            'password': password,

            'grant_type': 'password',
            'audience': config.KC_AUDIENCE,
            'client_id': config.KEYCLOAK_CLIENT_ID,
            'scope': config.KC_SCOPE,
            'client_secret': config.KEYCLOAK_CLIENT_SECRET,
        })
        resp.raise_for_status()
        tokens = resp.json()

        # Return the tokens
        return {
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        }
    except requests.exceptions.RequestException as e:
        logger.error("Failed to login to Keycloak: %s" % e)
        raise Unauthorized


def refresh(token_info, refresh_token):
    subject = token_info['sub'] if token_info is not None and 'sub' in token_info else None
    if subject is not None:
        try:
            # format: client_id=workbench-local&grant_type=refresh_token&client_secret=<secret>>&refresh_token=<token>
            # Refresh uses same Token URL as login, different parameter
            resp = requests.post(url=config.KC_TOKEN_URL,
                                 verify=config.SSL_VERIFY,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                 data={'client_id': config.KEYCLOAK_CLIENT_ID,
                                       'client_secret': config.KEYCLOAK_CLIENT_SECRET,
                                       'grant_type': 'refresh_token',
                                       'refresh_token': refresh_token})
            resp.raise_for_status()
            tokens = resp.json()

            # Return the tokens
            return {
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
        except requests.exceptions.RequestException as e:
            logger.error("Failed to refresh Keycloak token: %s" % e)
            raise Unauthorized

    return None


def service_account_login():
    try:
        # format: client_id=workbench-local&grant_type=refresh_token&client_secret=<secret>>&refresh_token=<token>
        # Refresh uses same Token URL as login, different parameter
        resp = requests.post(url=config.KC_TOKEN_URL,
                             verify=config.SSL_VERIFY,
                             headers={'Content-Type': 'application/x-www-form-urlencoded'},
                             data={
                                 'grant_type': 'client_credentials',
                                 'client_id': config.KEYCLOAK_CLIENT_ID,
                                 'client_secret': config.KEYCLOAK_CLIENT_SECRET
                             })
        resp.raise_for_status()
        tokens = resp.json()

        return {
            'access_token': tokens['access_token']
        }
    except requests.exceptions.RequestException as e:
        logger.error("Failed to login to Keycloak service account: %s" % e)
        raise Unauthorized


def logout(access_token, refresh_token):
    subject = access_token['sub'] if access_token is not None and 'sub' in access_token else None
    if subject is not None:
        try:
            resp = requests.post(url=config.KC_LOGOUT_URL,
                                 verify=config.SSL_VERIFY,
                                 data={
                                     'client_id': config.KEYCLOAK_CLIENT_ID,
                                     'client_secret': config.KEYCLOAK_CLIENT_SECRET,
                                     'refresh_token': refresh_token
                                 })
            resp.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError, requests.exceptions.Timeout) as e:
            logger.warning("Failed to logout from Keycloak: %s" % e)


# Returns default_cpu_req, default_cpu_lim, default_mem_req, default_mem_lim
# FIXME: Currently unused
def get_account_resource_limits(token_info):
    # TODO: fetch these from keycloak?
    username = token_info['sub']
    groups = token_info['roles']['realmAccess']
    if 'workbench-admin' in groups:
        return


# FIXME: Currently unused
def get_default_userapp_limits(token_info):
    # TODO: fetch these from keycloak?
    username = token_info['sub']
