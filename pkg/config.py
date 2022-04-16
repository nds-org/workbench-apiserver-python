import datetime
import os
import requests
import tempfile

import logging

from jose import jwk
from jose.utils import base64url_decode

logger = logging.getLogger('config')


DOMAIN = 'local.ndslabs.org'

# v1

# EtcdStore
ETCD_HOST = os.getenv('ETCD_HOST', '127.0.0.1')
ETCD_PORT = os.getenv('ETCD_PORT', 4001)
ETCD_BASE_PATH = os.getenv('ETCD_BASE_PATH', '/ndslabs')

# MongoStore
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://user:pass@localhost:27017/ndslabs')
MONGO_DB = os.getenv('MONGO_DB', 'ndslabs')

# Kubernetes
KUBE_HOST = os.getenv('KUBE_HOST', 'localhost')
KUBE_PORT = os.getenv('KUBE_PORT', 6443)
KUBE_TOKENPATH = os.getenv('KUBE_TOKENPATH', '/run/secrets/kubernetes.io/serviceaccount/token')
#KUBE_QPS = os.getenv('KUBE_QPS', 50)
#KUBE_BURST = os.getenv('KUBE_BURST', 100)

# v2?
KUBE_WORKBENCH_RESOURCE_PREFIX = ''
KUBE_WORKBENCH_NAMESPACE = 'workbench'
KUBE_PVC_STORAGECLASS = os.getenv('hostpath', None)

SWAGGER_URL = os.getenv('SWAGGER_URL', 'openapi/swagger-v1.yml')


# Downloads a remote swagger spec from the configured SWAGGER_URL and save it to a temp file.
# Returns the path to the temp file created.
def download_remote_swagger_to_temp_file(temp_file_name='swagger-keycloak.yml'):
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
KEYCLOAK_HOST = os.getenv('KEYCLOAK_HOST', 'http://localhost:8080')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'workbench-dev')
KC_REALM_URL = '%s/realms/%s' % (KEYCLOAK_HOST, KEYCLOAK_REALM)
KC_OIDC_PREFIX = '%s/protocol/openid-connect' % KC_REALM_URL
KC_TOKEN_URL = "%s/token" % KC_OIDC_PREFIX
KC_USERINFO_URL = "%s/userinfo" % KC_OIDC_PREFIX
KC_LOGOUT_URL = "%s/logout" % KC_OIDC_PREFIX
KC_AUTH_URL = "%s/auth" % KC_OIDC_PREFIX

# system-generated params
KC_ALGORITHM = os.getenv('KC_ALGORITHM', 'RS256')
KC_GRANT_TYPE = 'password'
KC_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'workbench-local')
KC_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', '')
KC_SCOPE = 'profile email openid workbench-accounts'

# system-specific config
# (create this Mapping in Keycloak)
KC_ISSUER = ''
KC_AUDIENCE = 'workbench-local'


# TODO: fetch token
# curl https://keycloak.workbench.ndslabs.org/auth/realms/workbench-dev/protocol/openid-connect/token -XPOST --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'client_id=workbench-local' --data-urlencode 'grant_type=password' --data-urlencode 'username=test' --data-urlencode 'password=mysamplepasswordissupersecure' --data-urlencode 'scope=openid' --data-urlencode 'client_secret=73305daa-c3d9-4ec7-aec0-caa9b030e182'

try:
    resp = requests.get(KC_REALM_URL)
    resp.raise_for_status()
    open_id_config = resp.json()
    # fetch from https://keycloak.workbench.ndslabs.org/auth/realms/workbench-dev
    KC_OIDC_PREFIX = open_id_config["token-service"]
    KC_TOKEN_URL = "%s/token" % KC_OIDC_PREFIX
    KC_USERINFO_URL = "%s/userinfo" % KC_OIDC_PREFIX
    KC_LOGOUT_URL = "%s/logout" % KC_OIDC_PREFIX
    KC_CERTS_URL = "%s/certs" % KC_OIDC_PREFIX
    resp = requests.get(KC_CERTS_URL)
    keys = resp.json()
    logger.info("Fetched keys: %s" % keys)
    KC_PUBLICKEY = jwk.construct(keys['keys'][0])
    logger.info("Using Keycloak Realm token service: %s" % KC_PUBLICKEY)
except requests.exceptions.RequestException as e:
    logger.error("Failed to fetch keycloak realm config: %s" % e)
    raise SystemExit(e)




