import connexion
import logging
import datetime
import os

#from jsonschema import validate
#from pkg import types
import six
from jose import JWTError, jwt, jws, JWSError
from werkzeug.exceptions import Unauthorized, Forbidden

from connexion.exceptions import Unauthorized

from pkg import config
from pkg.datastore import data_store

logger = logging.getLogger('pkg.auth.jwt')

ADMIN_USERS = config.ADMIN_USERS.split(",")


def expire_token(token):
    payload = safe_decode(token)
    payload['exp'] = datetime.datetime.utcnow()   # expire token now
    return jwt.encode(payload, config.JWT_SECRET, config.JWT_ALGORITHM)


def encode(username):
    #user = data_store.retrieve_user_by_username(username)

    iat = datetime.datetime.utcnow()
    exp = iat + config.JWT_TIMEOUT
    server = os.uname()[1]

    payload = {
        "exp": exp,
        "aud": config.JWT_AUDIENCE,
        "username": username,
        "sub": "example",
        "iat": iat,
        "server": server
    }

    return jwt.encode(payload, config.JWT_SECRET, config.JWT_ALGORITHM)


def safe_decode(jwt_token):
    try:
        return decode(jwt_token)
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)


def decode(jwt_token):
    if config.USE_KEYCLOAK:
        return jwt.decode(token=jwt_token, key=config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM], audience=config.JWT_AUDIENCE)


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
    # Check for "token" cookie first
    # If cookie not found, check for "X-API-TOKEN" header
    # If we still haven't found anything, check for "token" querystring param
    # Finally, fallback to default Authorization header if we are still without a token
    for token in [
        get_token_from_cookies(),
        get_token_from_headers(),
        get_token_from_querystring(),
        get_token_from_auth_header()
    ]:
        if token is not None:
            return token


def get_token_from_auth_header():
    if 'Authorization' in connexion.request.headers:
        bearer_str = connexion.request.headers.get('Authorization')
        # If the word "bearer" is included, return everything after that literal
        if bearer_str.lower().startswith('bearer '):
            return bearer_str.split(' ')[-1]
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


def get_username_from_token(token=None):
    if token is None:
        token = get_token()
    claims = safe_decode(token)
    return claims['preferred_username'] if 'preferred_username' in claims else claims['username']


def get_token_from_querystring():
    # querystring = querystring[1:] if querystring.startswith('?') else querystring

    if 'token' in connexion.request.args:
        return connexion.request.args.get('token')
    return None


def validate_apikey_querystring(apikey, required_scopes):
    if not apikey:
        #raise Unauthorized
        return None

    return validate_token(apikey, required_scopes)


def validate_auth_header(apikey, required_scopes):
    if not apikey:
        return None   # Missing credentials / token

    # format: bearer <jwt>
    # we only want the jwt, strip out the literal "bearer"
    token = apikey.split(" ")[-1]

    return validate_token(token, required_scopes)


def validate_apikey_header(apikey, required_scopes):
    if 'X-API-TOKEN' not in connexion.request.headers:
        #raise Unauthorized
        return None   # Missing credentials / token

    #token = get_token_from_cookies()
    return validate_token(apikey, required_scopes)


def validate_auth_cookie(cookies, required_scopes):
    if 'token' not in cookies:
        #raise Unauthorized
        return None   # Missing credentials / token

    token = get_token_from_cookies()
    return validate_token(token, required_scopes)


def validate_token(token, required_scopes):
    try:
        claims = decode(str(token))

        # TODO: Check authorization
        if required_scopes is not None:
            validate_scopes(required_scopes, claims)

        return claims   # Credentials fine, access granted
    except JWTError as e:
        logger.error('Failed to decode JWT: ', e)
        six.raise_from(Unauthorized, e)
        #raise Unauthorized
        return None   # Bad credentials / bad format


def validate_keycloak_role(required_role, roles):
    logger.info("Validating Keycloak required_role=%s, roles=%s" % (required_role, roles))
    if required_role not in roles:
        raise Forbidden


def validate_scopes(required_scopes, claims):
    if config.USE_KEYCLOAK:
        roles = claims['realm_access']['roles']
        if required_scopes is not None and 'workbench-admin' in required_scopes:
            validate_keycloak_role('workbench-admin', roles)
        if required_scopes is not None and 'workbench-accounts' in required_scopes:
            validate_keycloak_role('workbench-accounts', roles)
        if required_scopes is not None and 'workbench-catalog' in required_scopes:
            validate_keycloak_role('workbench-catalog', roles)
        if required_scopes is not None and 'workbench-dev' in required_scopes:
            validate_keycloak_role('workbench-dev', roles)
    else:
        username = claims['username']
        if username not in ADMIN_USERS:
            raise Forbidden

