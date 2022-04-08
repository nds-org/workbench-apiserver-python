from urllib.error import HTTPError

import connexion
import requests
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

    if config.USE_KEYCLOAK:
        try:
            tokens = keycloak.login(username, password)
            kube.init_user(username)
            token = tokens['access_token']
            #account = data_store.retrieve_user_by_username(username)
            #if account is None:
            #    hashed_password = bcrypt.hashpw(password.encode('ascii'), bcrypt.gensalt())
            #    account = data_store.create_user({'username': claims['sub'],
            #                                      'password': hashed_password,
            #                                      'email': claims['email'],
            #                                      'name': claims['name']})
            #    logger.info("First login detected - created shadow account: " % account)
            #elif not bcrypt.checkpw(password.encode('ascii'), account['password']):
            #    hashed_password = bcrypt.hashpw(password.encode('ascii'), bcrypt.gensalt())
            #    account['password'] = hashed_password
            #    data_store.update_user(account)
            #    logger.info("Password mismatch detected.. synced shadow account: " % account)
            return {'token': token}, 200, {'Set-Cookie': 'token=%s' % token}
        except requests.exceptions.HTTPError as e:
            # Intentionally vague public error message, verbose log
            logger.error('Failed keycloak login for username=%s: %s' % (username, str(e)))
            return {'error': 'Invalid credentials'}, 401
    else:
        account = data_store.retrieve_user_by_username(username)
        if account is None:
            # Intentionally vague public error message, verbose log
            return {'error': 'Invalid credentials'}, 401

        if bcrypt.checkpw(password.encode('ascii'), account['password']):
            token = jwt.encode(username)
            kube.init_user(username)
            return {'token': token}, 200, {'Set-Cookie': 'token=%s' % token}
        else:
            # Intentionally vague public error message, verbose log
            return {'error': 'Invalid credentials'}, 401


def delete_authenticate():
    # TODO: Do we store anything server-side related to sessions?
    if config.USE_KEYCLOAK:
        keycloak.logout()
        return 204, {'Set-Cookie': 'token=undefined'}
    else:
        existing_token = jwt.get_token()
        expired_token = jwt.expire_token(existing_token)

        # if so, clear it here
        return 204, {'Set-Cookie': 'token=%s' % expired_token}


def refresh_token():
    existing_token = jwt.get_token()
    token_json = jwt.safe_decode(existing_token)
    fresh_token = jwt.encode(token_json['username'])
    return {'token': fresh_token}, 501, {'Set-Cookie': 'token=%s' % fresh_token}


def check_token():
    existing_token = jwt.get_token()
    try:
        jwt.decode(existing_token)
        return 'Token is valid', 200
    except JWTError as e:
        return 'Invalid token', 401


def validate_o_auth_token():
    return '', 501
