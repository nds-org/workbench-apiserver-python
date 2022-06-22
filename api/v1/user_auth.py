import connexion
import requests
import time
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


def response(body, token_str=None, status=200, headers=None):
    if headers is None:
        headers = {}
    if token_str:
        claims = jwt.safe_decode(token_str)
        headers.add('Set-Cookie', jwt.get_token_cookie(token_str))
        return body, status, jwt.get_token_cookie(claims['sub'])
    return body, status, headers


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
    username = auth['username']
    password = auth['password']

    try:
        tokens = keycloak.login(username, password)
        kube.init_user(username)
        access_token = tokens['access_token']

        token_info = jwt.safe_decode(access_token)
        refresh_token_str = tokens['refresh_token']
        refr_token_info = jwt.decode_refresh_token(refresh_token_str)
        data_store.store_refresh_token(token_info=token_info, refr_token_str=refresh_token_str, refr_token_info=refr_token_info)

        jwt.update_access_token(username=username, access_token=access_token)
        #    logger.info("Password mismatch detected.. synced shadow account: " % account)
        return {'token': access_token}, 200, jwt.get_token_cookie(username)
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
        # Intentionally vague public error message, verbose log
        logger.error('Failed keycloak login for username=%s: %s' % (username, str(e)))
        return {'error': 'Invalid credentials'}, 401, jwt.clear_token_cookie(username)


def delete_authenticate():
    access_token = jwt.get_token()
    token_info = jwt.safe_decode(access_token)
    username = jwt.get_username_from_token(access_token)

    refresh_token = data_store.retrieve_refresh_token(token_info=token_info)
    if refresh_token is None:
        # Nothing to delete - noop
        return 204, jwt.clear_token_cookie()

    refresh_token_str = refresh_token['token']

    # Invalidate refresh token
    keycloak.logout(access_token=access_token, refresh_token=refresh_token_str)
    data_store.clear_refresh_token(token_info=token_info)
    jwt.update_access_token(username=username, access_token=None)

    # Invalidate any cookies
    return 204, jwt.clear_token_cookie(username=username)


def refresh_token(user, token_info):
    # Check for existing refresh token
    refresh_token = data_store.retrieve_refresh_token(token_info=token_info)
    if refresh_token is None:
        return {'error': 'Token has expired'}, 401, jwt.clear_token_cookie()

    refresh_token_str = refresh_token['token']

    tokens = keycloak.refresh(token_info, refresh_token_str)
    new_refr_token_str = tokens['refresh_token']
    refr_token_info = jwt.safe_decode()
    data_store.store_refresh_token(token_info=token_info, refr_token_str=new_refr_token_str, refr_token_info=refr_token_info)

    # Return new access token
    access_token = tokens['access_tokens']
    jwt.update_access_token(username=user, access_token=access_token)
    return {'token': access_token}, 200, jwt.get_token_cookie(access_token)


def check_token(user, token_info):
    try:
        if user != token_info['sub']:
            return {'error': 'Invalid token'}, 401
        # TODO: Check token expiry?
        #if token_info['exp'] < time.time():
        #    return {'error': 'Invalid token'}, 401
        return {'status': 'Token is valid'}, 200
    except (JWTError, JWSError, JWKError) as e:
        return {'error': 'Invalid token'}, 401


def validate_o_auth_token():
    return '', 501
