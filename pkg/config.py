import datetime
import os
import requests
import tempfile

import json
import logging

from jose import jwk
from jose.utils import base64url_decode


logger = logging.getLogger('config')

BACKEND_CFG_PATH = os.getenv('BACKEND_CFG_PATH', './env/backend.json')
FRONTEND_CFG_PATH = os.getenv('FRONTEND_CFG_PATH', './env/frontend.json')

# First fetch to /api/v1/version will cache this
VERSION_NUMBER = None

# Read app/env/backend.json and frontend/json
with open(FRONTEND_CFG_PATH) as f:
    frontend_config = json.load(f)
    logger.warning("frontend config: " + str(frontend_config))

with open(BACKEND_CFG_PATH) as b:
    # returns JSON object as a dict
    backend_config = json.load(b)
    logger.warning("backend config: " + str(backend_config))

# Read from env vars or fall back to values in backend.json config file
DEBUG = os.getenv('DEBUG', backend_config['debug'] if 'debug' in backend_config else 'false').lower() in ('true', '1', 't')
DOMAIN = os.getenv('DOMAIN', backend_config['domain'] if 'domain' in backend_config else 'local.ndslabs.org')
SSL_VERIFY = os.getenv('INSECURE_SSL_VERIFY',
                       backend_config['insecure_ssl_verify'] if 'insecure_ssl_verify' in backend_config else 'false'
                       ).lower() in ('true', '1', 't')

# MongoStore
MONGO_URI = os.getenv('MONGO_URI', backend_config['mongo']['uri'])
MONGO_DB = os.getenv('MONGO_DB', backend_config['mongo']['db'] if 'db' in backend_config['mongo'] else 'ndslabs')


# v2?
KUBE_WORKBENCH_RESOURCE_PREFIX = os.getenv('KUBE_WORKBENCH_RESOURCE_PREFIX', backend_config['resource_prefix'] if 'resource_prefix' in backend_config else '')
KUBE_WORKBENCH_NAMESPACE = os.getenv('KUBE_WORKBENCH_NAMESPACE', backend_config['namespace'] if 'namespace' in backend_config else '')
KUBE_WORKBENCH_SINGLEPOD = os.getenv('KUBE_WORKBENCH_SINGLEPOD', backend_config['userapps']['singlepod'] if 'userapps' in backend_config and 'singlepod' in backend_config['userapps'] else False)
KUBE_PVC_STORAGECLASS = os.getenv('KUBE_PVC_STORAGECLASS', backend_config['userapps']['home']['storage_class'] if 'userapps' in backend_config and 'home' in backend_config['userapps'] and 'storage_class' in backend_config['userapps']['home'] else None)

SWAGGER_URL = os.getenv('SWAGGER_URL', backend_config['swagger_url'] if 'swagger_url' in backend_config else 'openapi/swagger-v1.yml')


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


OAUTH_USERINFO_URL = os.getenv('OAUTH_USERINFO_URL', backend_config['oauth']['userinfoUrl'])

# Use central Keycloak
KEYCLOAK_HOST = os.getenv('KEYCLOAK_HOST', backend_config['keycloak']['hostname'])
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', backend_config['keycloak']['realmName'])
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', backend_config['keycloak']['clientId'])
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', backend_config['keycloak']['clientSecret'] if 'clientSecret' in backend_config['keycloak'] else '')

KC_REALM_URL = '%s/realms/%s' % (KEYCLOAK_HOST, KEYCLOAK_REALM)

# system-generated params
KC_ALGORITHM = os.getenv('KC_ALGORITHM', 'RS256')
KC_SCOPE = 'profile email openid roles'

# system-specific config
# (create this Mapping in Keycloak)
KC_ISSUER = os.getenv('KC_ISSUER', '')
KC_AUDIENCE = os.getenv('KC_AUDIENCE', 'workbench-local')

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
    logger.warning("Assuming running OAuth2 Proxy...")




