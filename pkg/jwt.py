import connexion
import logging
import datetime
import os

#from jsonschema import validate
#from pkg import types
import six
from jose import JWTError, jwt, jws, JWSError
from werkzeug.exceptions import Unauthorized

from pkg import config

logger = logging.getLogger('pkg.jwt')


def encode(user_id, user):
    iat = datetime.datetime.utcnow()
    exp = iat + config.JWT_TIMEOUT
    server = os.uname()[1]

    payload = {
        "exp": exp,
        "id": user_id,
        "iat": iat,
        "server": server,
        "user": user
    }

    return jwt.encode(payload, config.JWT_SECRET, config.JWT_ALGORITHM)


def safe_decode(jwt_token):
    try:
        return jwt.decode(jwt_token, config.JWT_SECRET, config.JWT_ALGORITHM)
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)


def decode(jwt_token):
    return jwt.decode(jwt_token, config.JWT_SECRET, config.JWT_ALGORITHM)


def get_secret(user, token_info) -> str:
    return '''
    You are user_id {user} and the secret is 'wbevuec'.
    Decoded token claims: {token_info}.
    '''.format(user=user, token_info=token_info)


def verify_token(token):
    try:
        jws.verify(token, config.JWT_SECRET, config.JWT_ALGORITHM)
        return True, 200
    except JWSError:
        return JWSError, 401


# Use this method to consistently check our default location for an auth token
def get_token():
    # Check cookie first
    token_ckes = get_token_from_cookies()
    if token_ckes is not None:
        return token_ckes

    # If cookie not found, check for header
    token_hdrs = get_token_from_headers()
    if token_hdrs is not None:
        return token_hdrs

    # Check for apiKey querystring param
    token_query = get_token_from_querystring()
    if token_query is not None:
        return token_query

    # Fallback to default Authorization/Bearer mechanism
    token_auth = get_token_from_auth_header()
    if token_auth is not None:
        return token_auth


def get_token_from_auth_header():
    if 'Authorization' in connexion.request.headers:
        bearer_str = connexion.request.headers.get('Authorization')
        # If the word "bearer" is included, remove it
        if bearer_str.startswith('Bearer ') or bearer_str.startswith('bearer '):
            bearer_str = bearer_str[7:]
        return bearer_str
    return None


def get_token_from_headers():
    if 'X-API-TOKEN' in connexion.request.headers:
        return connexion.request.headers.get('X-API-TOKEN')
    return None


def get_token_from_cookies():
    if 'token' in connexion.request.cookies:
        return connexion.request.cookies.get('token')
    return None


def get_username_from_token():
    token = get_token_from_headers()
    claims = safe_decode(token)
    return claims['namespace']


def get_token_from_querystring():
    if 'apiKey' in connexion.request.args:
        return connexion.request.args.get('apiKey')
    return None


def validate_apikey_querystring():
    try:
        # Fetch and decode X-API-TOKEN header
        token = get_token_from_querystring()
        #claims = jwt.decode(token)

        # TODO: Check authorization
        # return 403  # Credentials fine, but user is not allowed

        return 200   # Credentials fine, access granted
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)
        six.raise_from(Unauthorized, e)
        return 401   # Bad credentials / bad format


def validate_auth_header():
    if 'Authorization' not in connexion.request.headers:
        return 401   # Missing credentials / token

    try:
        # Fetch and decode X-API-TOKEN header
        token = get_token_from_auth_header()
        claims = jwt.decode(token)

        # TODO: Check authorization
        # return 403  # Credentials fine, but user is not allowed

        return 200   # Credentials fine, access granted
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)
        six.raise_from(Unauthorized, e)
        return 401   # Bad credentials / bad format


def validate_apikey_header():
    if 'X_API_TOKEN' not in connexion.request.headers:
        return 401   # Missing credentials / token

    try:
        # Fetch and decode X-API-TOKEN header
        token = get_token_from_headers()
        claims = jwt.decode(token)

        # TODO: Check authorization
        # return 403  # Credentials fine, but user is not allowed

        return 200   # Credentials fine, access granted
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)
        six.raise_from(Unauthorized, e)
        return 401   # Bad credentials / bad format


def validate_auth_cookie():
    if 'token' not in connexion.request.cookies:
        return 401   # Missing credentials / token

    try:
        # Fetch and decode Cookie
        token = get_token_from_cookies()
        claims = jwt.decode(token)

        # TODO: Check authorization
        # return 403  # Credentials fine, but user is not allowed

        return 200  # Credentials fine, access granted
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)
        six.raise_from(Unauthorized, e)
        return 401  # Bad credentials / bad format

