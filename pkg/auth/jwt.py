import connexion
import logging

import six
from pkg.auth import keycloak
from jose import jwt
from jose.exceptions import JWTError, JWSError, JWKError, ExpiredSignatureError
from werkzeug.exceptions import Forbidden

from connexion.exceptions import Unauthorized

from pkg import config
from pkg.db.datastore import data_store

logger = logging.getLogger('pkg.auth.jwt')


def safe_decode(jwt_token):
    try:
        return decode(jwt_token)
    except ExpiredSignatureError as e:
        logger.warning('Token is expired - attempting refresh: %s' % e)
    except (JWTError, JWSError, JWKError) as e:
        logger.error('Failed to decode JWT: %s' % e)


def decode(jwt_token):
    return jwt.decode(token=jwt_token, key=config.KC_PUBLICKEY, algorithms=["RS256"], audience=config.KC_AUDIENCE)


def decode_expired(jwt_token):
    return jwt.decode(token=jwt_token, key=config.KC_PUBLICKEY, algorithms=["RS256"], audience=config.KC_AUDIENCE, options={"verify_exp": False})


def decode_refresh_token(jwt_token):
    return jwt.decode(token=jwt_token, key=config.KC_PUBLICKEY, algorithms=["HS256"], audience=config.KC_REALM_URL, options={"verify_signature": False})


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
        return bearer_str.split(' ')[-1] if bearer_str.lower().startswith('bearer ') else bearer_str
    return None


def get_token_from_headers():
    return connexion.request.headers.get('X-API-TOKEN') if 'X-API-TOKEN' in connexion.request.headers else None


def get_token_from_cookies():
    return connexion.request.cookies.get('token') if 'token' in connexion.request.cookies else None


def get_token_from_querystring():
    return connexion.request.args.get('token') if 'token' in connexion.request.args else None


def get_username_from_token(token=None):
    if token is None:
        logger.warning("No token provided.. attempting lookup")
        token = get_token()
    if token is None:
        logger.error("Failed to find token.. cannot decode username")
        raise Unauthorized
    claims = safe_decode(token)

    if claims is None:
        logger.error("Failed to get username from token")
        raise Unauthorized
    return claims['sub'] if 'preferred_username' in claims else claims['sub']


def validate_apikey_querystring(apikey, required_scopes):
    return validate_token(apikey, required_scopes)


def validate_auth_header(apikey, required_scopes):
    # format: bearer <jwt>
    # we only want the jwt, strip out the literal "bearer"
    token = apikey.split(" ")[-1]

    return validate_token(token, required_scopes)


def validate_apikey_header(apikey, required_scopes):
    #token = get_token_from_cookies()
    return validate_token(apikey, required_scopes)


def validate_auth_cookie(cookies, required_scopes):
    if 'token' not in cookies:
        #raise Unauthorized
        return None   # Missing credentials / token

    token = get_token_from_cookies()
    return validate_token(token, required_scopes)


# FIXME: Currently unused
def validate_refresh_token(token, required_scopes):
    try:
        claims = decode_refresh_token(token)

        if required_scopes is not None:
            validate_scopes(required_scopes, claims)

        return claims
    except ExpiredSignatureError as e:
        logger.warning('Failed to refresh - refresh token is expired: %s' % e)
    except (JWTError, JWSError, JWKError) as e:
        logger.error('Failed to refresh access token: %s' % e)
    return None


def validate_token(token, required_scopes):
    try:
        claims = decode(str(token))

        # TODO: Check authorization
        if required_scopes is not None:
            validate_scopes(required_scopes, claims)

        return claims   # Credentials fine, access granted
    except ExpiredSignatureError as e:
        token_info = decode_expired(token)
        logger.warning('Token has expired - attempting refresh: %s' % token_info['session_state'])
        stored_token = data_store.retrieve_refresh_token(token_info=token_info)
        refresh_token_str = stored_token['token']
        tokens = keycloak.refresh(token_info=token_info, refresh_token=refresh_token_str)
        new_access_token = tokens['access_token']
        new_token_info = decode(new_access_token)
        new_refr_token = tokens['refresh_token']

        # Store new refresh token
        data_store.store_refresh_token(token_info=new_token_info, refresh_token=new_refr_token)

        logger.info('Token refreshed - session renewed: %s' % new_token_info['session_state'])
        # Return decoded new access token
        return decode(str(new_access_token))
    except (JWTError, JWSError, JWKError) as e:
        logger.error('Failed to decode JWT: ', e)
        six.raise_from(Unauthorized, e)
        #raise Unauthorized
        return None   # Bad credentials / bad format


def validate_role(required_role, roles):
    logger.info("Validating Keycloak required_role=%s, roles=%s" % (required_role, roles))
    if required_role not in roles:
        raise Forbidden


def validate_scopes(required_scopes, claims):
    roles = claims['realm_access']['roles']
    if required_scopes is not None and 'workbench-admin' in required_scopes:
        validate_role('workbench-admin', roles)
    if required_scopes is not None and 'workbench-accounts' in required_scopes:
        validate_role('workbench-accounts', roles)
    if required_scopes is not None and 'workbench-catalog' in required_scopes:
        validate_role('workbench-catalog', roles)
    if required_scopes is not None and 'workbench-dev' in required_scopes:
        validate_role('workbench-dev', roles)

