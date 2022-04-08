import connexion
from jose import JWTError
from werkzeug.exceptions import Unauthorized

from pkg import config, kube
from pkg.auth import jwt, keycloak
from pkg.datastore import data_store
import bcrypt
import logging

logger = logging.getLogger('api.v1.user_auth')


def run():
    logging.info("Token info - " + connexion.context['token_info'])

    logging.info("Auth info - " + connexion.request.auth)
    return None


def post_authenticate(auth):
    # req_json = connexion.request.json
    # auth_body = req_json['auth']
    auth_body = auth['auth']
    username = auth_body['username']
    password = auth_body['password']

    account = data_store.retrieve_user_by_username(username)
    if account is None:
        # Intentionally vague public error message, verbose log
        return {'error': 'Invalid credentials'}, 401

    if config.USE_KEYCLOAK:
        try:
            tokens = keycloak.login(username, password)
            kube.init_user(username)
            token = tokens['access_token']
            return {'token': token}, 200, {'Set-Cookie': 'token=%s' % token}
        except Unauthorized as e:
            logger.error('Failed keycloak login for %s: %s' % (username, str(e)))
            return {'error': 'Invalid credentials'}, 401
    else:
        if bcrypt.checkpw(password.encode('ascii'), account['password']):
            token = jwt.encode(username)
            kube.init_user(username)
            return {'token': token}, 200, {'Set-Cookie': 'token=%s' % token}
        else:
            # Intentionally vague public error message, verbose log
            return {'error': 'Invalid credentials'}, 401


def delete_authenticate():
    # TODO: Do we store anything server-side related to sessions?
    existing_token = jwt.get_token()
    expired_token = jwt.expire_token(existing_token)

    # if so, clear it here
    return expired_token, 200, {'Set-Cookie': 'token=%s' % expired_token}


def refresh_token():
    existing_token = jwt.get_token()
    token_json = jwt.safe_decode(existing_token)
    token = {'token': jwt.encode(token_json['username'])}
    return token, 501


def check_token():
    existing_token = jwt.get_token()
    try:
        jwt.decode(existing_token)
        return 'Token is valid', 200
    except JWTError as e:
        return 'Invalid token', 401


def validate_o_auth_token():
    return '', 501
