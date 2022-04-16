import requests
from werkzeug.exceptions import Unauthorized

from pkg import config
import logging

logger = logging.getLogger("pkg.auth.keycloak")


def login(username, password):
    try:
        resp = requests.post(config.KC_TOKEN_URL, {
            'username': username,
            'password': password,

            'audience': config.KC_AUDIENCE,
            'client_id': config.KC_CLIENT_ID,
            'grant_type': config.KC_GRANT_TYPE,
            'scope': config.KC_SCOPE,
            'client_secret': config.KC_CLIENT_SECRET,
        })
        resp.raise_for_status()
        tokens = resp.json()

        # Return the tokens
        return {
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        }
    except requests.exceptions.RequestException as e:
        logger.error("Failed to refresh Keycloak token: %s" % e)
        raise Unauthorized


def refresh(token_info, refresh_token):
    subject = token_info['sub'] if token_info is not None and 'sub' in token_info else None
    if subject is not None:
        try:
            # format: client_id=workbench-local&grant_type=refresh_token&client_secret=<secret>>&refresh_token=<token>
            # Refresh uses same Token URL as login, different parameter
            resp = requests.post(url=config.KC_TOKEN_URL,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                 data={'client_id': config.KC_CLIENT_ID,
                                       'client_secret': config.KC_CLIENT_SECRET,
                                       'grant_type': 'refresh_token',
                                       'refresh_token': refresh_token})
            resp.raise_for_status()
            tokens = resp.json()

            # Return the tokens
            return {
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
        except requests.exceptions.RequestException as e:
            logger.error("Failed to refresh Keycloak token: %s" % e)
            raise Unauthorized

    return None


def logout(access_token, refresh_token):
    subject = access_token['sub'] if access_token is not None and 'sub' in access_token else None
    if subject is not None:
        try:
            resp = requests.post(config.KC_LOGOUT_URL, {
                'client_id': config.KC_CLIENT_ID,
                'client_secret': config.KC_CLIENT_SECRET,
                'refresh_token': refresh_token
            })
            resp.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError, requests.exceptions.Timeout) as e:
            logger.warning("Failed to logout from Keycloak: %s" % e)





