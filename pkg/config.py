import datetime
import os
import requests
import tempfile

import logging

logger = logging.getLogger('config')


DOMAIN = 'local.ndslabs.org'

# comma-delimited list of usernames of admin users
ADMIN_USERS = os.getenv('ADMIN_USERS', 'test,demo')

# v1

# EtcdStore
ETCD_HOST = os.getenv('ETCD_HOST', '127.0.0.1')
ETCD_PORT = os.getenv('ETCD_PORT', 4001)
ETCD_BASE_PATH = os.getenv('ETCD_BASE_PATH', '/ndslabs')

# MongoStore
MONGO_HOST = os.getenv('MONGO_HOST', '127.0.0.1')
MONGO_PORT = os.getenv('MONGO_PORT', 27017)
MONGO_DATABASE = os.getenv('MONGO_DB', 'ndslabs')

# Kubernetes
KUBE_HOST = os.getenv('KUBE_HOST', 'localhost')
KUBE_PORT = os.getenv('KUBE_PORT', 6443)
KUBE_TOKENPATH = os.getenv('KUBE_TOKENPATH', '/run/secrets/kubernetes.io/serviceaccount/token')
KUBE_QPS = os.getenv('KUBE_QPS', 50)
KUBE_BURST = os.getenv('KUBE_BURST', 100)


# v2
MONGO_USER = 'admin'
MONGO_PASS = 'mysupersecretamazingawesomepasswordthatnobodycouldeverguess'
MONGO_URI = 'mongodb://%s:%s@%s:%s/%s' % (MONGO_USER, MONGO_PASS, MONGO_HOST, MONGO_PORT, MONGO_DATABASE)


KUBE_WORKBENCH_RESOURCE_PREFIX = ''
KUBE_WORKBENCH_NAMESPACE = 'workbench'
KUBE_SINGLEPOD = False   # TODO: Should we continue want to support this?
KUBE_PVC_STORAGECLASS = 'hostpath'

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


# JWT Auth
JWT_SECRET = os.getenv('JWT_SECRET', 'thisisnotverysecret')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'RS256')
JWT_EXP_DELTA_MINS = os.getenv('JWT_EXP_DELTA_MINS', 300)
JWT_TIMEOUT = datetime.timedelta(minutes=JWT_EXP_DELTA_MINS)
JWT_AUDIENCE = 'workbench-local'

# Use central Keycloak?
KEYCLOAK_HOST = os.getenv('KEYCLOAK_HOST', 'https://keycloak.workbench.ndslabs.org')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'workbench-dev')
USE_KEYCLOAK = False if KEYCLOAK_HOST == '' or KEYCLOAK_REALM == '' else True

if not USE_KEYCLOAK:
    logger.warning('Using local JWT implementation. Please configure KC_HOST and KC_REALM ' +
                   'to use Keycloak JWT authentication instead.')
else:
    KC_REALM_URL = '%s/auth/realms/%s' % (KEYCLOAK_HOST, KEYCLOAK_REALM)
    KC_OIDC_PREFIX = '%s/protocol/openid-connect' % KC_REALM_URL
    KC_TOKEN_URL = "%s/token" % KC_OIDC_PREFIX
    KC_USERINFO_URL = "%s/userinfo" % KC_OIDC_PREFIX
    KC_LOGOUT_URL = "%s/logout" % KC_OIDC_PREFIX

    # system-generated params
    KC_GRANT_TYPE = 'password'
    KC_CLIENT_ID = 'workbench-local'
    KC_CLIENT_SECRET = '73305daa-c3d9-4ec7-aec0-caa9b030e182'
    KC_SCOPE = 'openid'

    # system-specific config
    # (create this Mapping in Keycloak)
    KC_ISSUER = ''

    # Name of the cookie where tokens are stored
    KC_TOKENS_COOKIE_NAME = 'tokens'

    # TODO: fetch token
    # curl https://keycloak.workbench.ndslabs.org/auth/realms/workbench-dev/protocol/openid-connect/token -XPOST --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'client_id=workbench-local' --data-urlencode 'grant_type=password' --data-urlencode 'username=test' --data-urlencode 'password=mysamplepasswordissupersecure' --data-urlencode 'scope=openid' --data-urlencode 'client_secret=73305daa-c3d9-4ec7-aec0-caa9b030e182'

    try:
        resp = requests.get(KC_REALM_URL)
        resp.raise_for_status()
        open_id_config = resp.json()
        # fetch from https://keycloak.workbench.ndslabs.org/auth/realms/workbench-dev
        KC_PUBLICKEY_BODY = open_id_config['public_key']
        JWT_SECRET = '''
        -----BEGIN PUBLIC KEY-----
        %s
        -----END PUBLIC KEY-----
        ''' % KC_PUBLICKEY_BODY
    except requests.exceptions.RequestException as e:
        logger.error("Failed to fetch keycloak realm config: %s" % e)
        raise SystemExit(e)




