import logging
from builtins import range

from pkg import kube
from pkg.auth import jwt
from pkg.datastore import data_store

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


def list_userapps():
    token = jwt.get_token()
    claims = jwt.safe_decode(token)

    username = jwt.get_username_from_token(token)

    userapps = data_store.fetch_userapps(username)

    return userapps, 200


def get_service_port_numbers(port):
    return port['number']


def to_spec_map(specs, existing_map=None):
    spec_map = existing_map if existing_map is not None else {}
    for spec in specs:
        spec_key = spec['key']
        spec_map[spec_key] = spec
    return spec_map


def create_userapp(stack):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    stack['creator'] = username
    #stack['_id'] = generate_unique_id(username)

    spec_map = to_spec_map(data_store.fetch_all_appspecs_for_user(username))

    #try:
    kube.create_userapp(username=username, userapp=stack, spec_map=spec_map)
    stack = data_store.create_userapp(stack)

    return stack, 201
    #except Exception as e:
    #    logger.error('Failed to create userapp: %s' % str(e))
    #    return 'Error', 400

    #return 'Something went wrong', 500


def get_userapp_by_id(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims['username']

    userapp = data_store.retrieve_userapp_by_id(namespace, userapp_id=stack_id)

    return userapp, 200


def update_userapp(stack_id, stack):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    if stack['id'] != stack_id:
        return 'Bad Request: ID mismatch', 400
    if stack['creator'] != username:
        return 'Only the owner may modify a userapp', 403

    updated = data_store.update_userapp(stack)

    return stack, 200

def delete_userapp(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    # Verify that this user is the owner
    userapp = data_store.retrieve_userapp_by_id(stack_id)
    if userapp['creator'] != username:
        return 'Only the owner may delete a userapp', 403

    try:
        deleted = data_store.delete_userapp(stack_id)
        kube.destroy_userapp(username, userapp)
    except Exception as e:
        logger.error('Failed to delete userapp: ' % str(e))

    return '', 200


def rename_userapp(stack_id, name):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != username:
        return 'Only the owner may rename a userapp', 403

    # Change the name
    userapp['name'] = name
    update_userapp(stack_id, userapp)

    return userapp, 200


def get_stack_service_logs(stack_service_id):
    segments = stack_service_id.split('-')
    if segments.length != 2:
        return 'Malformed stack service id', 400

    stack_id = segments[0]
    service_key = segments[1]

    # Lookup userapp
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Validation
    if userapp is None:
        return 'Stack ID %s not found' % (stack_id), 404

    # Find the target in the app's service list
    for s in userapp.services:
        if s.key == service_key:
            return s.logs, 200

    return 'Service key %s not found on Stack ID %s' % (service_key, stack_id), 404


def quickstart_stack(key):
    token = jwt.get_token()
    username = jwt.get_username_from_token(token)

    # TODO: Check if user already has an instance of this app
    # TODO: If it exists, start it up and return
    # TODO: If it does not exist, create, start, then return

    return '', 501


def start_stack(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    # Lookup userapp using the id
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != username:
        return 'Only the owner may launch a userapp', 403

    # TODO: Create Deployment in Kubernetes

    # TODO: Mark userapp as STARTING, then return

    # TODO: Eventually, Pod is Running and event watchers
    #    should update userapp state to STARTED

    return '', 202


def stop_stack(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    # Lookup userapp using the id
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != username:
        return 'Only the owner may shutdown a userapp', 403

    # TODO: Delete Deployment in Kubernetes

    # TODO: Mark userapp as STOPPING, then return

    # TODO: Eventually, Pod is gone and event watchers
    #    should update userapp state to STOPPED

    return '', 202


def get_key_from_appspec(appspec):
    return appspec.key


def get_config_from_appspec(appspec):
    return appspec.config


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


