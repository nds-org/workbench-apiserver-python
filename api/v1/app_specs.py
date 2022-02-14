import connexion
import logging
from pkg import jwt
from pkg.datastore import data_store

logger = logging.getLogger('api.v1.app_specs')


def create_service(service):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    service['creator'] = namespace
    service['catalog'] = 'user'

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

    if catalog == 'system':
        services = data_store.fetch_system_appspecs()
        return services, 200

    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    if claims is None:
        return 'Not authorized', 401

    username = claims.username

    if catalog == 'user':
        services = data_store.fetch_user_appspecs(username)
        return services, 200
    else:  # catalog == all or anything else
        services = data_store.fetch_all_appspecs_for_user(username)
        return services, 200


def get_service_by_id(service_id):
    token = connexion.request.cookies.get('token')
    claims = jwt.safe_decode(token)
    namespace = claims['namespace']

    # Most lookups will likely be from the system catalog
    appspec = data_store.retrieve_system_appspec_by_key(service_id)
    if appspec is not None:
        return appspec, 200
    else:
        # User spec not found, check system catalog
        appspec = data_store.retrieve_user_appspec_by_key(namespace, service_id)

        if appspec is not None:
            return appspec, 200
        else:
            return 'Not found', 404


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





