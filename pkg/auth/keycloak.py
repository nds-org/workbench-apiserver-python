import requests
import base64
import connexion

from pkg import config
from jose import jwt
import logging
import json


logger = logging.getLogger("pkg.auth.keycloak")


def login(username, password):
    resp = requests.post(config.KC_TOKEN_URL, {
        'username': username,
        'password': password,

        'audience': config.JWT_AUDIENCE,
        'client_id': config.KC_CLIENT_ID,
        'grant_type': config.KC_GRANT_TYPE,
        'scope': config.KC_SCOPE,
        'client_secret': config.KC_CLIENT_SECRET,
    })

    resp.raise_for_status()
    resp_json = resp.json()

    # Provide access to account resources
    return {
        'access_token': resp_json['access_token'],
        'refresh_token': resp_json['refresh_token'],
    }


def logout():
    resp = requests.post(config.KC_LOGOUT_URL, {
        'client_id': config.KC_CLIENT_ID,
        'client_secret': config.KC_CLIENT_SECRET,
        'refresh_token': get_refresh_token()
    })
    resp.raise_for_status()


def get_user_info():
    headers = { 'Authorization': 'Bearer %s' % get_access_token() }
    resp = requests.get(config.KC_USERINFO_URL, headers=headers)
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
        access_token_jwt = jwt.decode(token, config.JWT_SECRET,
                                      algorithms=[config.JWT_ALGORITHM],
                                      audience=config.JWT_AUDIENCE)
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
    return jwt.decode(access_token, config.JWT_SECRET,
                      algorithms=[config.JWT_ALGORITHM],
                      audience='workbench-local')

