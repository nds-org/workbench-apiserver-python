import json

import requests
import logging
from pkg.config import SSL_VERIFY, OAUTH_USERINFO_URL
import connexion

logger = logging.getLogger('pkg.auth.oauth2')


#
# Expected UserInfo format:
#
# {
#   "email": "test@localhost",
#   "groups": [
#     "/workbench-users",                   # Groups
#     "role:workbench-user",                # Realm Roles
#     "role:workbench-local:client-role"    # Client Roles
#   ],
#   "sub": "test"
# }
# TODO: x-tokenInfoUrl can't handle insecure SSL
def userinfo(access_token) -> dict:
    try:
        resp = requests.get(url=OAUTH_USERINFO_URL,
                            verify=SSL_VERIFY,
                            cookies={"_oauth2_proxy": access_token})
        resp.raise_for_status()
        user = resp.json()

        roles = []
        for grp in user['groups']:
            roles.append(grp)

        # TODO: Hoping that oauth2-proxy enhances support for providing arbitrary token claims from OIDC
        # See https://github.com/oauth2-proxy/oauth2-proxy/issues/834
        return {
            'email': user['email'],
            'groups': roles,
            # 'family_name': user['family_name'],
            # 'given_name': user['given_name'],
            'sub': user['preferredUsername'].replace('@', '').replace('.', '')
        }
    except Exception as e:
        logger.warning("OAuth2 token verification failed: " + str(e))
        pass


def get_token_from_cookies(cookies=None):
    if cookies is None:
        cookies = connexion.request.cookies
    return cookies.get('_oauth2_proxy') if '_oauth2_proxy' in cookies else None


def validate_auth_cookie(cookies, required_scopes):
    token = get_token_from_cookies()
    return userinfo(token)
