import logging
from builtins import range

from pkg import kube
from pkg.auth import jwt
from pkg.db.datastore import data_store

import time
from random import seed
from random import randint

logger = logging.getLogger('api.v1.user_apps')

seed(time.time() * 1000)


def generate_random_id():
    # generate 5 random digits to form a userapp Id
    new_id = 's'
    for d in range(0, 5):
        new_id += str(randint(0, 9))

    return new_id


def generate_unique_id(username):
    while True:
        # Generate random userapp id
        userapp_id = generate_random_id()

        # Ensure that this id is unique
        namespace = kube.get_resource_namespace(username)
        userapp = data_store.retrieve_userapp_by_id(namespace, userapp_id)

        # No match found - id is unique!
        if userapp is None:
            return userapp_id


def list_userapps(user, token_info):
    userapps = data_store.fetch_userapps(user)

    return userapps, 200


def get_service_port_numbers(port):
    return port['number']


def to_spec_map(specs, existing_map=None):
    spec_map = existing_map if existing_map is not None else {}
    for spec in specs:
        spec_key = spec['key']
        spec_map[spec_key] = spec
    return spec_map


def update_userapp_replicas(username, userapp_id, replicas):
    userapp = data_store.retrieve_userapp_by_id(userapp_id=userapp_id, username=username)
    if userapp is None:
        return False
    spec_key = userapp['key']

    name = kube.get_resource_name(userapp_id, spec_key)
    namespace = kube.get_resource_namespace(username)
    result = kube.patch_scale_deployment(deployment_name=name, namespace=namespace, replicas=replicas)

    if result is None:
        return False

    return True


def create_userapp(stack, user, token_info):
    stack['creator'] = user
    stack_id = generate_unique_id(user)
    stack['id'] = stack['_id'] = stack_id

    # Set stack service ID on each dependency
    for svc in stack['services']:
        service_key = svc['service']
        ssid = '%s-%s' % (stack_id, service_key)
        svc['id'] = ssid
        svc['endpoints'] = []


    spec_map = to_spec_map(data_store.fetch_all_appspecs_for_user(user))

    try:
        # Create service(s) / ingress / deployment
        kube.create_userapp(username=user, userapp=stack, spec_map=spec_map)

        # Save metadata to database
        stack = data_store.create_userapp(stack)

        # Return success
        return stack, 201
    except Exception as e:
        # Cleanup failed userapp resources
        kube.destroy_userapp(username=user, userapp=stack)
        logger.error('Failed to create userapp: %s' % str(e))
        return {'error': 'Failed to create userapp: %s' % str(e)}, 400


def get_userapp_by_id(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims['username']

    userapp = data_store.retrieve_userapp_by_id(namespace, userapp_id=stack_id)

    return userapp, 200


def update_userapp(stack_id, stack, user, token_info):
    if stack['id'] != stack_id:
        return {'error': 'Bad Request: ID mismatch'}, 400, jwt.get_token_cookie(user)
    if stack['creator'] != user:
        return {'error': 'Only the owner may modify a userapp'}, 403, jwt.get_token_cookie(user)

    updated = data_store.update_userapp(stack)
    # TODO: check matched_count vs modified_count?
    return data_store.retrieve_userapp_by_id(username=user, userapp_id=stack_id), 200, jwt.get_token_cookie(user)


def delete_userapp(stack_id, user, token_info):
    # Verify that this user is the owner
    userapp = data_store.retrieve_userapp_by_id(username=user, userapp_id=stack_id)
    if userapp is None:
        return {'error': 'No userapp found with id=%s' % stack_id}, 404, jwt.get_token_cookie(user)
    if userapp['creator'] != user:
        return {'error': 'Only the owner may delete a userapp'}, 403, jwt.get_token_cookie(user)

    try:
        kube.destroy_userapp(username=user, userapp=userapp)
        logger.info('Cleaned up the user app: %s' % stack_id)

        deleted = data_store.delete_userapp(username=user, userapp_id=stack_id)

        # Verify deletion was successful using deleted_count
        if deleted.deleted_count > 0:
            return 204, jwt.get_token_cookie(user)
        else:
            return {'error': 'Failed to delete userapp=%s: deletion failed' % stack_id}, 500, jwt.get_token_cookie(user)
    except Exception as e:
        logger.error('Failed to delete userapp: %s' % str(e))
        return {'error': 'Failed to delete userapp: %s' % str(e)}, 500, jwt.get_token_cookie(user)


def rename_userapp(stack_id, name, user, token_info):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != username:
        return {'error': 'Only the owner may rename a userapp'}, 403, jwt.get_token_cookie(user)

    # Change the name
    userapp['name'] = name
    return update_userapp(stack_id=stack_id, stack=userapp, user=user, token_info=token_info)


def get_stack_service_logs(stack_service_id, user, token_info):
    segments = stack_service_id.split('-')
    if segments.length != 2:
        return {'error': 'Malformed stack service id'}, 400, jwt.get_token_cookie(user)

    stack_id = segments[0]
    service_key = segments[1]

    # Lookup userapp
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Validation
    if userapp is None:
        return {'error': 'Stack ID=%s not found' % stack_id}, 404, jwt.get_token_cookie(user)

    # Find the target in the app's service list
    for s in userapp.services:
        if s.key == service_key:
            return s.logs, 200

    return {'error': 'Service key %s not found on Stack ID %s' % (service_key, stack_id)}, 404, jwt.get_token_cookie(user)


def quickstart_stack(key, user, token_info):
    # token = jwt.get_token()
    # username = jwt.get_username_from_token(token)

    # TODO: Check if user already has an instance of this app
    # TODO: If it exists, start it up and return
    # TODO: If it does not exist, create, start, then return

    return '', 501


def start_stack(stack_id, user, token_info):
    # Lookup userapp using the id
    userapp = data_store.retrieve_userapp_by_id(userapp_id=stack_id, username=user)

    # Verify that this user is the owner
    if userapp['creator'] != user:
        return {'error': 'Only the owner may launch a userapp'}, 403, jwt.get_token_cookie(user)

    userapp['status'] = 'starting'

    # TODO: Eventually, Pod is Running and event watchers
    #    should update userapp state to STARTED
    if update_userapp_replicas(username=user, userapp_id=stack_id, replicas=1):
        data_store.update_userapp(userapp)
        return {'status': userapp['status']}, 202, jwt.get_token_cookie(user)
    else:
        return {'status': 'error',
                'error': 'failed to set replicas=1 for %s' % stack_id}, 400, jwt.get_token_cookie(user)


def stop_stack(stack_id, user, token_info):
    # Lookup userapp using the id
    userapp = data_store.retrieve_userapp_by_id(username=user, userapp_id=stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != user:
        return {'error': 'Only the owner may shutdown a userapp'}, 403, jwt.get_token_cookie(user)

    userapp['status'] = 'stopping'

    # TODO: Eventually, Pod is gone and event watchers
    #    should update userapp state to STOPPED
    if update_userapp_replicas(username=user, userapp_id=stack_id, replicas=0):
        data_store.update_userapp(userapp)
        return {'status': userapp['status']}, 202, jwt.get_token_cookie(user)
    else:
        return {'status': 'error',
                'error': 'failed to set replicas=0 for %s' % stack_id}, 400, jwt.get_token_cookie(user)


# Returns True if update was successful
def update_userapp_status(stack_id, service_key, new_status, new_endpoints, user, token_info):
    logger.info('Got new endpoints: %s' % str(new_endpoints))

    userapp_id = stack_id
    userapp = data_store.retrieve_userapp_by_id(userapp_id=userapp_id, username=user)
    services = userapp['services']
    # short-circuit
    service_keys = [x['service'] for x in services]

    if service_key not in service_keys:
        logger.error('Service not found in stack: %s %s-%s - %s' %
                     (user, userapp_id, service_key, service_keys))
        return {'error': 'not found'}, 404, jwt.get_token_cookie(user)

    service = [x for x in services if x['service'] == service_key][0]

    if service['status'] == new_status:
        logger.debug('No-op: Status for %s %s-%s is already %s' %
                     (user, userapp_id, service_key, new_status))
        return {'status': service['status']}, 304, jwt.get_token_cookie(user)

    service['status'] = new_status

    # if all services running, set whole app state to running
    running_services = [x['service'] for x in services if x['status'] == 'running']
    if len(running_services) == len(services):
        userapp['status'] = 'running'

    # if all services stopped, set whole app state to stopped
    stopped_services = [x['service'] for x in services if x['status'] == 'stopped']
    if len(stopped_services) == len(services):
        userapp['status'] = 'stopped'

    result = data_store.update_userapp(userapp)

    # naive error handling:
    #return {'status': new_status}, 200, jwt.get_token_cookie(user)

    if result.modified_count > 0 and result.matched_count == result.modified_count:
        logger.debug('Status updated successfully: %s %s-%s -> %s' %
                     (user, userapp_id, service_key, new_status))
        return {'status': new_status}, 200, jwt.get_token_cookie(user)
    elif result.matched_count == 0:
        logger.warning('No matches for status update: (%s, %s, %s, %s)' %
                       (userapp_id, user, service_key, new_status))
        return {'status': 'no matches'}, 404, jwt.get_token_cookie(user)
    elif result.modified_count < result.matched_count:
        logger.warning('Matches found, but were only partially updated (%d/%d): (%s, %s, %s, %s)' %
                       (result.modified_count, result.matched_count, userapp_id, user, service_key, new_status))
        return {'status': 'partial success (%d/%d)' % (result.modified_count, result.matched_count)}, 207, jwt.get_token_cookie(user)
    elif result.modified_count == 0:
        logger.warning('Matches found, but none were updated: (%s, %s, %s, %s)' %
                       (userapp_id, user, service_key, new_status))
        return {'status': service['status']}, 304, jwt.get_token_cookie(user)

    logger.warning('Something went wrong, and nothing happened: (%s, %s, %s, %s)' %
                   (userapp_id, user, service_key, new_status))
    return {'error': 'unknown'}, 500, jwt.get_token_cookie(user)


def get_key_from_appspec(appspec):
    return appspec['key']


def get_config_from_appspec(appspec):
    return appspec['config']


def get_stack_configs(services=None):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    configs = []
    all_appspecs = data_store.fetch_all_appspecs_for_user(username)
    all_appspec_keys = list(map(get_key_from_appspec, all_appspecs))

    if services is None:
        return map(get_config_from_appspec, all_appspecs), 200
    else:
        for s in services:
            index = all_appspec_keys.index(s)
            if index is None:
                return 'Failed to find service: %s' % s, 400

            appspec = all_appspecs[index]

            configs.append(appspec.config)

    return configs, 200


