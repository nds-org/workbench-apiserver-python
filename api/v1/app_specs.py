import logging

from pkg.auth import jwt
from pkg.db.datastore import data_store
from pkg.db.mongo import MongoStore

from pkg.openapi import types

logger = logging.getLogger('api.v1.app_specs')


def import_appspecs_recursive():
    # TODO: Rely on the Helm postinstall / init_container / Job for this
    return


# TODO: parameter of "services" keys to include
# TODO: Should this be a Job instead? init_container?
def import_appspec(appspec):  # input: single json file

    return appspec


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


def create_service(service, user, token_info):
    if not service or not service['key']:
        return {'error': 'Invalid spec: no spec provided'}, 400

    if '$oid' in service:
        service.pop('$oid')
    if 'id' in service:
        service.pop('id')
    if '_id' in service:
        service.pop('_id')

    service['creator'] = user
    catalog = service['catalog'] if 'catalog' in service else 'user'
    dependencies = service['depends'] if 'depends' in service else []

    # Ensure that all dependencies exist
    missing_deps = []
    all_specs = data_store.fetch_all_appspecs_for_user(user)
    for dep in dependencies:
        if len([spec['key'] for spec in all_specs if dep['key'] == spec['key']]) == 0:
            missing_deps.append(dep['key'])

    if len(missing_deps) > 0:
        return {'error': 'Invalid spec: missing dependencies: %s' % missing_deps}, 400

    if catalog == 'user':
        if 'creator' not in service:
            return {'error': 'User appspec must specify a creator'}, 400
        else:
            service_key = service['key']
            if is_service_key_unique(user, service_key):
                new_spec = data_store.create_user_appspec(service)
                return new_spec, 201
            else:
                return {'error': 'Spec key already exists: %s' % service_key}, 409
    elif catalog == 'system':
        jwt.validate_scopes(['workbench-admin'], token_info)
        service_key = service['key']
        if is_service_key_unique(user, service_key):
            new_spec = data_store.create_system_appspec(service)
            return new_spec, 201
        else:
            return {'error': 'Spec key already exists: %s' % service_key}, 409


def list_services_for_user(user, token_info):
    return data_store.fetch_user_appspecs(user), 200


def list_services():
    return data_store.fetch_system_appspecs(), 200


def list_services_all(user, token_info):
    return data_store.fetch_system_appspecs() + data_store.fetch_user_appspecs(user), 200


def get_service_by_id(service_id, user, token_info):
    # No token (or appspec not found), but we can still check system catalog
    appspec = data_store.retrieve_system_appspec_by_key(service_id)
    if appspec is None:
        appspec = data_store.retrieve_user_appspec_by_key(user, service_id)

    if appspec is not None:
        return appspec, 200
    else:
        return {'error': 'Spec key=%s not found' % service_id}, 404


def update_service(service_id, service, user, token_info):
    spec_key = service['key']
    if spec_key != service_id:
        return {'error': 'Key cannot be changed'}, 400
    catalog = service['catalog'] if 'catalog' in service else 'user'

    if catalog == 'user':
        existing_spec = data_store.retrieve_user_appspec_by_key(user, spec_key)
        if existing_spec is None:
            return {'error': 'cannot update user app spec: user spec not found with key=%s' % spec_key}, 404
        if user != existing_spec['creator']:
            return {'error': 'appspec only allows editing by the creator'}, 403
        if 'creator' in service and existing_spec['creator'] != service['creator']:
            return {'error': 'appspec cannot change creator'}, 403

        # Image is required
        existing_spec['image'] = service['image']

        # Basic Info
        existing_spec['label'] = service['label'] if 'label' in service else ''
        existing_spec['access'] = service['access'] if 'access' in service else 'external'
        existing_spec['display'] = service['display'] if 'display' in service else 'stack'
        existing_spec['info'] = service['info'] if 'info' in service else ''
        existing_spec['logo'] = service['logo'] if 'logo' in service else ''
        existing_spec['maintainer'] = service['maintainer'] if 'maintainer' in service else ''
        existing_spec['description'] = service['description'] if 'description' in service else ''

        # Command / args
        existing_spec['command'] = service['command'] if 'command' in service else []
        existing_spec['args'] = service['args'] if 'arg' in service else []

        # Other tabs
        existing_spec['ports'] = service['ports'] if 'ports' in service else []
        existing_spec['config'] = service['config'] if 'config' in service else []
        existing_spec['depends'] = service['depends'] if 'depends' in service else []
        existing_spec['volumeMounts'] = service['volumeMounts'] if 'volumeMounts' in service else []

        # Currently Hidden
        existing_spec['resourceLimits'] = service['resourceLimits'] if 'resourceLimits' in service else {}
        existing_spec['readinessProbe'] = service['readinessProbe'] if 'readinessProbe' in service else {}
        existing_spec['repositories'] = service['repositories'] if 'repositories' in service else []
        existing_spec['securityContext'] = service['securityContext'] if 'securityContext' in service else {}

        # TODO: should we use NotModified?
        updated = data_store.update_user_appspec(user, existing_spec)
        status_code = 200   # if updated > 0 else 304
        return data_store.retrieve_user_appspec_by_key(user, spec_key), status_code

    elif catalog == 'system':
        # Admins only: check token for required roles
        jwt.validate_scopes(['workbench-admin'], token_info)
        existing_spec = data_store.retrieve_system_appspec_by_key(spec_key)
        if existing_spec is None:
            return {'error': 'cannot update system app spec: system spec not found with key=%s' % spec_key}, 404

        # TODO: should we use NotModified?
        updated = data_store.update_system_appspec(service)
        # TODO: check matched_count vs modified_count?
        status_code = 200 if updated.modified_count > 0 else 304
        return data_store.retrieve_system_appspec_by_key(spec_key), status_code

    else:
        return {'error': 'appspec must have a valid catalog value'}, 400


def delete_service(service_id, user, token_info):
    # Check for user appspec
    service = data_store.retrieve_user_appspec_by_key(user, service_id)
    if service is not None:
        if user != service['creator']:
            return {'error': 'appspec only allows deletion by the creator'}, 403
        # Attempt to delete the appspec
        deleted = data_store.delete_user_appspec(user, service_id)

        # Verify deletion was successful using deleted_count
        if deleted.deleted_count > 0:
            return 204
        else:
            return {'error': 'Failed to delete user spec key=%s: deletion failed' % service_id}, 500

    # Admins only: check token for required role
    jwt.validate_scopes(['workbench-admin'], token_info)

    # Check for system appspec
    service = data_store.retrieve_system_appspec_by_key(service_id)
    if service is not None:
        # Attempt to delete the appspec
        deleted = data_store.delete_system_appspec(service_id)

        # Verify deletion was successful using deleted_count
        if deleted.deleted_count > 0:
            return 204
        else:
            return {'error': 'Failed to delete system spec key=%s: deletion failed' % service_id}, 500

    else:
        return {'error': 'Spec key=%s not found in either user or system catalog' % service_id}, 404





