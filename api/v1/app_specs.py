import connexion
import logging
from pkg import jwt
from pkg.datastore import data_store
from pkg.utils import find

logger = logging.getLogger('api.v1.app_specs')


def create_service(service):
    if 'catalog' not in service:
        return {'error': 'No catalog value was specified'}, 400
    elif service['catalog'] == 'system':
        return data_store.create_system_appspec(service), 201
    elif service['catalog'] == 'user':
        if 'creator' not in service:
            return {'error': 'User appspec must specify a creator'}, 400
        else:
            return data_store.create_user_appspec(service), 201


def list_services(catalog='all'):
    args = connexion.request.args
    catalog_arg = args.get('catalog')  # ??
    logging.info("Get services with catalog - "+catalog)
    logging.info("Get services with catalog arg - "+catalog_arg)

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


def get_service_by_id(service_id):
    token = connexion.request.cookies.get('token')
    claims = jwt.safe_decode(token)
    namespace = claims['namespace']

    all_appspecs = data_store.fetch_all_appspecs_for_user(namespace)
    appspec = find(lambda x: x.get("key") == service_id, all_appspecs)

    return appspec, 200


def update_service(service_id, service):
    if service['id'] != service_id:
        return {'error': 'invalid id mismatch'}, 400

    namespace = jwt.get_username_from_token()

    if service['catalog'] == 'user':
        if namespace != service['creator']:
            return {'error': 'appspec only allows editing by the creator'}, 403
        return data_store.update_user_appspec(namespace, service), 200
    elif service['catalog'] == 'system':
        # TODO: Admins only
        return data_store.update_system_appspec(service), 200
    else:
        return {'error': 'appspec must have a valid catalog value'}, 400


def delete_service(service_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims['username']
    service = data_store.retrieve_user_appspec_by_key(namespace, service_id)

    if service['catalog'] == 'user':
        if namespace != service['creator']:
            return {'error': 'appspec only allows editing by the creator'}, 403
        return data_store.update_user_appspec(namespace, service), 200
    elif service['catalog'] == 'system':
        # TODO: Admins only
        return data_store.update_system_appspec(service), 200
    else:
        return {'error': 'appspec must have a valid catalog value'}, 400


def list_services_old():
    args = connexion.request.args
    catalog = args.get('catalog')
    logging.info("Get services with catalog - "+catalog)

    services = []
    #if catalog == 'system':
    #    services = etcdClient.getSystemServices()
    #elif catalog == 'user':
    #    services = etcdClient.getUserServices()
    #else:  # catalog == all or others
    #    services = etcdClient.getAllServices()

    if 'x_access_token' in connexion.request.headers:
        token = connexion.request.headers['X-Access-Token']
        print(token)
    print("---- start ----")
    print(connexion.request.headers)
    print("==== end ====")

    return services, 200





