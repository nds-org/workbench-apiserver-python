import connexion

import logging

from pkg import jwt
from pkg.datastore import data_store

logger = logging.getLogger('api.v1.user_apps')


def list_services():
    args = connexion.request.args
    catalog = args.get('catalog')
    logging.info("Get services with catalog - "+catalog)

    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = claims.username

    if catalog == 'system':
        services = data_store.fetch_system_appspecs()
        return services, 200
    elif catalog == 'user':
        services = data_store.fetch_user_appspecs(username)
        return services, 200
    else:  # catalog == all or others
        services = data_store.fetch_all_appspecs_for_user(username)
        return services, 200
