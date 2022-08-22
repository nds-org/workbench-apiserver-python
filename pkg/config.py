import datetime
import os
import requests
import tempfile

import json
import logging

from jose import jwk
from jose.utils import base64url_decode


logger = logging.getLogger('config')
DEBUG = os.getenv('DEBUG', 'false').lower() in ('true', '1', 't')

DOMAIN = 'local.ndslabs.org'

# Read app/env/backend.json and frontend/json
loaded_backend = False
loaded_frontend = False

if not loaded_frontend:
    with open('./env/frontend.json') as f:
        frontend_config = json.load(f)
        for i in frontend_config.items():
            print(i)
        loaded_frontend = True

if not loaded_backend:
    with open('./env/backend.json') as f:
        # returns JSON object as a dict
        backend_config = json.load(f)
        for i in backend_config.items():
            print(i)
        loaded_backend = True

# Internal messaging
ZMQ_SOCKET_SERVER_URI = 'tcp://*:5001'
ZMQ_SOCKET_CLIENT_URI = 'tcp://localhost:5002'

SSL_VERIFY = os.getenv('INSECURE_SSL_VERIFY', 'false').lower() in ('true', '1', 't')

# v1
DEFAULT_ACCT_MEM = '8GB'
DEFAULT_ACCT_CPU = '2M'

DEFAULT_MEM_REQ = '512MB'
DEFAULT_MEM_LIM = '1GB'
DEFAULT_CPU_REQ = '100m'
DEFAULT_CPU_LIM = '500m'

DEV_MEM_REQ = '1GB'
DEV_MEM_LIM = '2GB'
DEV_CPU_REQ = '500m'
DEV_CPU_LIM = '1M'

ADMIN_MEM_REQ = '512MB'
ADMIN_MEM_LIM = '1GB'
ADMIN_CPU_REQ = '100M'
ADMIN_CPU_LIM = '2M'

# EtcdStore
ETCD_HOST = os.getenv('ETCD_HOST', '127.0.0.1')
ETCD_PORT = os.getenv('ETCD_PORT', 4001)
ETCD_BASE_PATH = os.getenv('ETCD_BASE_PATH', '/ndslabs')

# MongoStore
MONGO_URI = os.getenv('MONGO_URI', backend_config['mongo']['uri'])
MONGO_DB = os.getenv('MONGO_DB', backend_config['mongo']['db'] if 'db' in backend_config['mongo'] else 'ndslabs')


# Kubernetes
KUBE_HOST = os.getenv('KUBE_HOST', 'localhost')
KUBE_PORT = os.getenv('KUBE_PORT', 6443)
KUBE_TOKENPATH = os.getenv('KUBE_TOKENPATH', '/run/secrets/kubernetes.io/serviceaccount/token')
#KUBE_QPS = os.getenv('KUBE_QPS', 50)
#KUBE_BURST = os.getenv('KUBE_BURST', 100)


CALLBACK_SERVICE_ACCOUNT_JWT = os.getenv('CALLBACK_SERVICE_ACCOUNT_JWT', '')
CALLBACK_HOST = os.getenv('CALLBACK_HOST', 'http://localhost:5000')
CALLBACK_URL_TEMPLATE = os.getenv('CALLBACK_URL_TEMPLATE', CALLBACK_HOST + '/api/v1/stacks/%s/status')

# v2?
KUBE_WORKBENCH_RESOURCE_PREFIX = ''
KUBE_WORKBENCH_NAMESPACE = os.getenv('KUBE_WORKBENCH_NAMESPACE', 'workbench')
KUBE_WORKBENCH_SINGLEPOD = os.getenv('KUBE_WORKBENCH_SINGLEPOD', 'true').lower() in ('true', '1', 't')
KUBE_PVC_STORAGECLASS = os.getenv('hostpath', None)

SWAGGER_URL = os.getenv('SWAGGER_URL', 'openapi/swagger-v1.yml')


# Downloads a remote swagger spec from the configured SWAGGER_URL and save it to a temp file.
# Returns the path to the temp file created.
def download_remote_swagger_to_temp_file(temp_file_name='swagger-tmp.yml'):
    try:
        # fetch swagger spec, parse response
        swagger_response = requests.get(SWAGGER_URL)
        swagger_response.raise_for_status()
        swagger_spec_text = swagger_response.text

        # save swagger spec to temp file
        temp_file_path = os.path.join(tempfile.gettempdir(), temp_file_name)
        with open(temp_file_path, 'w') as f:
            f.write(swagger_spec_text)

        return temp_file_path
    except requests.exceptions.RequestException as e:
        logger.error("Failed to fetch swagger spec: %s" % e)
        raise SystemExit(e)


# Use central Keycloak
KEYCLOAK_HOST = os.getenv('KEYCLOAK_HOST', backend_config['keycloak']['hostname'])
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', backend_config['keycloak']['realmName'])
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', backend_config['keycloak']['clientId'])
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', backend_config['keycloak']['clientSecret'] if 'clientSecret' in backend_config['keycloak'] else '')

KC_REALM_URL = '%s/realms/%s' % (KEYCLOAK_HOST, KEYCLOAK_REALM)
KC_OIDC_PREFIX = '%s/protocol/openid-connect' % KC_REALM_URL
KC_TOKEN_URL = "%s/token" % KC_OIDC_PREFIX
KC_USERINFO_URL = "%s/userinfo" % KC_OIDC_PREFIX
KC_LOGOUT_URL = "%s/logout" % KC_OIDC_PREFIX
KC_AUTH_URL = "%s/auth" % KC_OIDC_PREFIX

# system-generated params
KC_ALGORITHM = os.getenv('KC_ALGORITHM', 'RS256')
KC_GRANT_TYPE = 'password'
KC_SCOPE = 'profile email openid workbench-accounts'

# system-specific config
# (create this Mapping in Keycloak)
KC_ISSUER = ''
KC_AUDIENCE = 'workbench-local'

SOCK_PING_INTERVAL = int(os.getenv('SOCK_PING_INTERVAL', 25))
max_msg_size = os.getenv('SOCK_MAX_MESSAGE_SIZE', None)
SOCK_MAX_MESSAGE_SIZE = int(max_msg_size) if max_msg_size else max_msg_size

# TODO: fetch token
# curl https://keycloak.workbench.ndslabs.org/auth/realms/workbench-dev/protocol/openid-connect/token -XPOST --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'client_id=workbench-local' --data-urlencode 'grant_type=password' --data-urlencode 'username=test' --data-urlencode 'password=mysamplepasswordissupersecure' --data-urlencode 'scope=openid' --data-urlencode 'client_secret=73305daa-c3d9-4ec7-aec0-caa9b030e182'

try:
    resp = requests.get(KC_REALM_URL, verify=SSL_VERIFY)
    resp.raise_for_status()
    open_id_config = resp.json()
    # fetch from https://keycloak.workbench.ndslabs.org/auth/realms/workbench-dev
    KC_OIDC_PREFIX = open_id_config["token-service"]
    KC_TOKEN_URL = "%s/token" % KC_OIDC_PREFIX
    KC_USERINFO_URL = "%s/userinfo" % KC_OIDC_PREFIX
    KC_LOGOUT_URL = "%s/logout" % KC_OIDC_PREFIX
    KC_CERTS_URL = "%s/certs" % KC_OIDC_PREFIX
    resp = requests.get(KC_CERTS_URL, verify=SSL_VERIFY)
    keys = resp.json()
    logger.info("Fetched keys: %s" % keys)
    KC_PUBLICKEY = jwk.construct(keys['keys'][0])
    logger.info("Using Keycloak Realm token service: %s" % KC_PUBLICKEY)
except requests.exceptions.RequestException as e:
    logger.error("Failed to fetch keycloak realm config: %s" % e)
    raise SystemExit(e)




