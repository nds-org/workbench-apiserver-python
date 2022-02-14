import connexion
from jose import JWTError

from pkg import jwt
from pkg.datastore import data_store
import bcrypt
import logging

logger = logging.getLogger('api.v1.user_auth')


def run():
    logging.info("Token info - " + connexion.context['token_info'])

    logging.info("Auth info - " + connexion.request.auth)
    return None


def post_authenticate():
    req_json = connexion.request.json
    username = req_json['username']
    password = req_json['password']

    account = data_store.retrieve_user_by_namespace(username)

    if bcrypt.checkpw(password, account.password):
        token = {'token': jwt.encode(username)}
        return token, 200
    else:
        return '', 401


def delete_authenticate():
    # TODO: Do we store anything server-side related to sessions?
    # if so, clear it here
    return '', 200


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
