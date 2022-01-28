import connexion

import logging

logger = logging.getLogger('api.v1.user_apps')

def list_services():
    args = connexion.request.args
    catalog = args.get('catalog')
    logging.info("Get services with catalog - "+catalog)

    services = []
    if catalog == 'system':
        services = etcdClient.getSystemServices()
    elif catalog == 'user':
        services = etcdClient.getUserServices()
    else:  # catalog == all or others
        services = etcdClient.getAllServices()

    if 'x_access_token' in connexion.request.headers:
        token = connexion.request.headers['X-Access-Token']
        print(token)
    print("---- start ----")
    print(connexion.request.headers)
    print("==== end ====")

    return services, 200