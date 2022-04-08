import connexion
import logging
from pkg.auth import jwt
from pkg.datastore import data_store

from pkg import mongo, types

logger = logging.getLogger('api.v1.app_specs')


def import_appspecs(git_repo):
    # TODO: script out recursive import of JSON files from target git repo

    return


# TODO: Is manual validation ever needed?
def validate_service(service):
    try:
        types.validate_instance(service, 'service')
    except Exception as e:
        return {'error': 'Validation failed for service: %s' % str(e)}, 400


def is_service_key_unique(username, service_key):
    existing_user_spec = data_store.retrieve_user_appspec_by_key(username, service_key)
    if existing_user_spec is not None:
        logger.error("Error: failed to create spec key=%s - user spec already exists")
        return False
    existing_system_spec = data_store.retrieve_system_appspec_by_key(service_key)
    if existing_system_spec is not None:
        logger.error("Error: failed to create spec key=%s - system spec already exists")
        return False

    return True

def create_service(service):
    token = jwt.get_token()
    username = jwt.get_username_from_token(token)

    service['creator'] = username
    catalog = service['catalog'] if 'catalog' in service else 'user'

    if catalog == 'user':
        if 'creator' not in service:
            return {'error': 'User appspec must specify a creator'}, 400
        else:
            service_key = service['key']
            if is_service_key_unique(username, service_key):
                new_spec = data_store.create_user_appspec(service)
                return new_spec, 201
            else:
                return {'error': 'Spec key already exists: %s' % service_key}, 409
    elif catalog == 'system':
        service_key = service['key']
        jwt.validate_scopes(['workbench-admin'], jwt.safe_decode(token))
        if is_service_key_unique(username, service_key):
            new_spec = data_store.create_system_appspec(service)
            return new_spec, 201
        else:
            return {'error': 'Spec key already exists: %s' % service_key}, 409


def list_services(catalog='all'):
    logging.info("Get services with catalog - "+catalog)

    if catalog == 'system':
        services = data_store.fetch_system_appspecs()
        return mongo.parse_json(services), 200

    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    if claims is None:
        return {'error': 'Not authorized'}, 401

    username = jwt.get_username_from_token(token)

    if catalog == 'user':
        services = data_store.fetch_user_appspecs(username)
        return mongo.parse_json(services), 200
    else:  # catalog == all or anything else
        services = data_store.fetch_all_appspecs_for_user(username)
        return mongo.parse_json(services), 200


def get_service_by_id(service_id):
    token = jwt.get_token()
    username = jwt.get_username_from_token(token)

    # Most lookups will likely be from the system catalog
    appspec = data_store.retrieve_system_appspec_by_key(service_id)
    if appspec is not None:
        appspec['_id'] = str(appspec['_id'])
        return appspec, 200
    else:
        # User spec not found, check system catalog
        appspec = data_store.retrieve_user_appspec_by_key(username, service_id)

        if appspec is not None:
            appspec['_id'] = str(appspec['_id'])
            return appspec, 200
        else:
            return 'Not found', 404


def update_service(service_id, service):
    spec_key = service['key']
    if spec_key != service_id:
        return {'error': 'Key cannot be changed'}, 400
    catalog = service['catalog'] if 'catalog' in service else 'user'
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    if catalog == 'user':
        existing_spec = data_store.retrieve_user_appspec_by_key(username, spec_key)
        if existing_spec is None:
            return {'error': 'cannot update user app spec: user spec not found with key=%s' % spec_key}, 404
        if username != existing_spec['creator']:
            return {'error': 'appspec only allows editing by the creator'}, 403
        if 'creator' in service and existing_spec['creator'] != service['creator']:
            return {'error': 'appspec cannot change creator'}, 403
        return data_store.update_user_appspec(username, service), 200
    elif catalog == 'system':
        # Admins only: check token for required roles
        jwt.validate_scopes(['workbench-admin'], claims)
        existing_spec = data_store.retrieve_system_appspec_by_key(spec_key)
        if existing_spec is None:
            return {'error': 'cannot update system app spec: system spec not found with key=%s' % spec_key}, 404
        return data_store.update_system_appspec(service), 200
    else:
        return {'error': 'appspec must have a valid catalog value'}, 400


def delete_service(service_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    # Check for user appspec
    service = data_store.retrieve_user_appspec_by_key(username, service_id)
    if service is not None:
        if username != service['creator']:
            return {'error': 'appspec only allows deletion by the creator'}, 403
        # Attempt to delete the appspec
        if data_store.delete_user_appspec(username, service_id) > 0:
            return 204
        else:
            return {'error': 'Failed to delete user spec key=%s: deletion failed' % service_id}, 500

    # Admins only: check token for required role
    jwt.validate_scopes(['workbench-admin'], claims)

    # Check for system appspec
    service = data_store.retrieve_system_appspec_by_key(service_id)
    if service is not None:
        # Attempt to delete the appspec
        if data_store.delete_system_appspec(service_id) > 0:
            return 204
        else:
            return {'error': 'Failed to delete system spec key=%s: deletion failed' % service_id}, 500

    else:
        return {'error': 'Spec key=%s not found in either user or system catalog' % service_id}, 404





