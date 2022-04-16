import connexion
import requests
from jose import JWTError, JWSError
from jose.exceptions import JWKError

from pkg import kube
from pkg.auth import jwt, keycloak
from pkg.db.datastore import data_store
import logging

logger = logging.getLogger('api.v1.user_auth')


def run():
    logging.info("Token info - " + connexion.context['token_info'])

    logging.info("Auth info - " + connexion.request.auth)
    return None


SET_COOKIE_STR = 'token=%s'
CLEAR_COOKIE_STR = 'token=undefined; Expires=0'


def set_token_cookie(token_str):
    return {'Set-Cookie': 'token=%s' % token_str}


def clear_token_cookie():
    return {'Set-Cookie', 'token=undefined; Expires=0'}


def new_user(username, password, email, name):
    return {
        'username': username,
        'password': password,
        'email': email,
        'name': name
    }


def post_authenticate(auth):
    # req_json = connexion.request.json
    # auth_body = req_json['auth']
    auth_body = auth['auth']
    username = auth_body['username']
    password = auth_body['password']

    try:
        tokens = keycloak.login(username, password)
        kube.init_user(username)
        access_token = tokens['access_token']

        token_info = jwt.safe_decode(access_token)
        refresh_token_str = tokens['refresh_token']
        data_store.store_refresh_token(token_info=token_info, refresh_token=refresh_token_str)

        #    logger.info("Password mismatch detected.. synced shadow account: " % account)
        return {'token': access_token}, 200, set_token_cookie(access_token)
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
        # Intentionally vague public error message, verbose log
        logger.error('Failed keycloak login for username=%s: %s' % (username, str(e)))
        return {'error': 'Invalid credentials'}, 401, clear_token_cookie()


def delete_authenticate():
    access_token = jwt.get_token()
    token_info = jwt.safe_decode(access_token)
    username = jwt.get_username_from_token(access_token)

    refresh_token = data_store.retrieve_refresh_token(token_info=token_info)
    if refresh_token is None:
        # Nothing to delete - noop
        return 204, clear_token_cookie()

    refresh_token_str = refresh_token['token']

    # Invalidate refresh token
    keycloak.logout(access_token=access_token, refresh_token=refresh_token_str)
    data_store.clear_refresh_token(token_info=token_info)

    # Invalidate any cookies
    return 204, clear_token_cookie()


def refresh_token(user, token_info):
    # Check for existing refresh token
    refresh_token = data_store.retrieve_refresh_token(token_info=token_info)
    if refresh_token is None:
        return {'error': 'Token has expired'}, 401, clear_token_cookie()

    refresh_token_str = refresh_token['token']

    tokens = keycloak.refresh(token_info, refresh_token_str)
    data_store.store_refresh_token(token_info=token_info, refresh_token=tokens['refresh_token'])

    # Return new access token
    access_token = tokens['access_tokens']
    return {'token': access_token}, 200, set_token_cookie(access_token)


def check_token(user, token_info):
    try:
        jwt.decode(token_info)
        return {'status': 'Token is valid'}, 200
    except (JWTError, JWSError, JWKError) as e:
        return {'error': 'Invalid token'}, 401


def validate_o_auth_token():
    return '', 501
