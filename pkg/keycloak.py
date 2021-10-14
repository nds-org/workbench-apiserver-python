import requests
import base64
import connexion

from pkg import config
from jose import jwt
import logging
import json

# system-generated params
KC_GRANT_TYPE = 'password'
KC_CLIENT_ID = 'workbench-local'
KC_CLIENT_SECRET = '73305daa-c3d9-4ec7-aec0-caa9b030e182'
KC_SCOPE = 'openid'

# system-specific config
# (create this Mapping in Keycloak)
KC_AUDIENCE = 'workbench-local'

KC_HOST = 'https://keycloak.workbench.ndslabs.org'
KC_REALM = 'workbench-dev'
KC_URL_PREFIX = '%s/auth/realms/%s/protocol/openid-connect' % (KC_HOST, KC_REALM)

KC_TOKEN_PATH_SUFFIX = 'token'
KC_USERINFO_PATH_SUFFIX = 'userinfo'
KC_LOGOUT_PATH_SUFFIX = 'logout'

KC_TOKEN_URL = "%s/%s" % (KC_URL_PREFIX, KC_TOKEN_PATH_SUFFIX)
KC_USERINFO_URL = "%s/%s" % (KC_URL_PREFIX, KC_USERINFO_PATH_SUFFIX)
KC_LOGOUT_URL = "%s/%s" % (KC_URL_PREFIX, KC_LOGOUT_PATH_SUFFIX)

TOKENS_COOKIE_NAME = 'tokens'

logger = logging.getLogger("keycloak")


def login(username, password):
    resp = requests.post(KC_TOKEN_URL, {
        'username': username,
        'password': password,

        'audience': KC_AUDIENCE,
        'client_id': KC_CLIENT_ID,
        'grant_type': KC_GRANT_TYPE,
        'scope': KC_SCOPE,
        'client_secret': KC_CLIENT_SECRET,
    })

    resp.raise_for_status()
    resp_json = resp.json()

    # Provide access to account resources
    return {
        'access_token': resp_json['access_token'],
        'refresh_token': resp_json['refresh_token'],
    }


def logout():
    resp = requests.post(KC_LOGOUT_URL, {
        'client_id': KC_CLIENT_ID,
        'client_secret': KC_CLIENT_SECRET,
        'refresh_token': get_refresh_token()
    })
    resp.raise_for_status()


def get_user_info():
    headers = { 'Authorization': 'Bearer %s' % get_access_token() }
    resp = requests.get(KC_USERINFO_URL, headers=headers)
    resp.raise_for_status()
    return resp.json()


def cookie_token_auth(cookies, required_scopes=None):
    access_token_jwt = get_access_token_jwt()
    logging.debug("Checking cookie token: " + str(access_token_jwt))

    if len(access_token_jwt) > 0:
        return access_token_jwt

    # optional: raise exception for custom error response
    return None


def apikey_auth(token, required_scopes=None):
    logging.debug("Checking apikey token: " + str(token))
    if token != '':
        access_token_jwt = jwt.decode(token, config.KC_PUBLICKEY,
                                      algorithms=[config.JWT_ALGORITHM],
                                      audience='workbench-local')
        return access_token_jwt

    # optional: raise exception for custom error response
    return None


def encode_tokens(obj):
    tokens_bytes = json.dumps(obj).encode("utf-8")
    return base64.b64encode(tokens_bytes).decode("utf-8")


def decode_tokens(tokens_b64):
    tokens_str = base64.b64decode(tokens_b64)
    return json.loads(tokens_str)


def get_refresh_token():
    tokens = decode_tokens(connexion.request.cookies['tokens'])
    return tokens["refresh_token"]


def get_access_token():
    tokens = decode_tokens(connexion.request.cookies['tokens'])
    return tokens["access_token"]


def get_access_token_jwt():
    access_token = get_access_token()
    return jwt.decode(access_token, config.KC_PUBLICKEY,
                      algorithms=[config.JWT_ALGORITHM],
                      audience='workbench-local')


