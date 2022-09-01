import connexion
import logging

import six
from pkg.auth import keycloak, oauth2
from jose import jwt
from jose.exceptions import JWTError, JWSError, JWKError, ExpiredSignatureError
from werkzeug.exceptions import Forbidden

from connexion.exceptions import Unauthorized

from pkg import config
from pkg.db.datastore import data_store

logger = logging.getLogger('pkg.auth.jwt')

SET_COOKIE_STR = 'token=%s; Path=/'
CLEAR_COOKIE_STR = 'token=undefined; Path=/; Expires=0'
access_tokens = {}


def get_access_token(username):
    return access_tokens.get(username, None)


def update_access_token(username, access_token):
    access_tokens[username] = access_token


def get_token_cookie(username, access_token_str=None):
    if access_token_str is None:
        access_token_str = get_access_token(username)
    if access_token_str is None:
        return {}
    return {'Set-Cookie': SET_COOKIE_STR % access_token_str}


def clear_token_cookie(username):
    update_access_token(username, None)
    return {'Set-Cookie', CLEAR_COOKIE_STR}


def safe_decode(jwt_token):
    try:
        return decode(jwt_token)
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
    ]:
        if token is not None:
            return token


def get_token_from_headers(headers=None):
    if headers is None:
        headers = connexion.request.headers
    return headers.get('X-API-TOKEN') if 'X-API-TOKEN' in headers else None


def get_token_from_cookies(cookies=None):
    if cookies is None:
        cookies = connexion.request.cookies
    return cookies.get('token') if 'token' in cookies else None


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
    if 'preferredUsername' in claims:
        return claims['preferredUsername']
    if 'username' in claims:
        return claims['username']

    # Fallback to well-known 'sub' claim
    return claims['sub']


def validate_apikey_querystring(apikey, required_scopes):
    #logger.info("Checking for auth (querystring): %s" % apikey)
    return validate_token(apikey, required_scopes)


def validate_auth_header(auth_header, required_scopes):
    #logger.debug("Checking for auth (header): %s" % apikey)
    # format: bearer <jwt>
    # we only want the jwt, strip out the literal "bearer"
    token = auth_header.split(" ")[-1]

    return validate_token(token, required_scopes)


def validate_apikey_header(apikey, required_scopes):
    logger.debug("Checking for auth (X-API-KEY): %s" % apikey)
    return validate_token(apikey, required_scopes)


def validate_auth_cookie(cookies, required_scopes):
    #logger.debug("Checking for auth (cookie): %s" % cookies)
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
        #logger.info("Checking for auth: " + token)
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

        # XXX: Replace new access token in cookie
        # connexion.request.cookies.add('token', new_access_token)

        # Store new refresh token
        new_refr_token_info = decode_refresh_token(new_refr_token)
        data_store.store_refresh_token(token_info=new_token_info, refr_token_str=new_refr_token, refr_token_info=new_refr_token_info)
        update_access_token(username=new_token_info['sub'], access_token=new_access_token)

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


def tokeninfo(token):
    logger.info("Decoding token: %s" % token)
    return safe_decode(token)
