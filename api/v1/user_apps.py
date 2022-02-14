import connexion

import logging

from pkg import jwt
from pkg.datastore import data_store

import time
from random import seed
from random import randint

logger = logging.getLogger('api.v1.user_apps')

seed(time.time() * 1000)

def generate_random_id():
    # generate 5 random digits to form a userapp Id
    d1 = randint(0, 9)
    d2 = randint(0, 9)
    d3 = randint(0, 9)
    d4 = randint(0, 9)
    d5 = randint(0, 9)


    return 's%d%d%d%d%d' % (d1, d2, d3, d4, d5)

def generate_unique_id():
    while True:
        # Generate random userapp id
        userapp_id = generate_random_id()

        # Ensure that this id is unique
        userapp = data_store.retrieve_userapp_by_id(userapp_id)

        # No match found - id is unique!
        if userapp is None:
            return userapp_id


def list_userapps():
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    userapps = data_store.fetch_userapps(namespace)

    return userapps, 200


def create_userapp(stack):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    stack['creator'] = namespace
    stack['id'] = generate_unique_id()

    created = data_store.create_userapp(stack)

    return created, 201


def get_userapp_by_id(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    userapp = data_store.retrieve_userapp_by_id(namespace, stack_id)

    return userapp, 200


def update_userapp(stack_id, stack):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    if stack['id'] != stack_id:
        return 'Bad Request: ID mismatch', 400
    if stack['creator'] != namespace:
        return 'Only the owner may modify a userapp', 403

    updated = data_store.update_userapp(stack)

    return stack, 200

def delete_userapp(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    # Verify that this user is the owner
    userapp = data_store.retrieve_userapp_by_id(stack_id)
    if userapp['creator'] != namespace:
        return 'Only the owner may delete a userapp', 403

    deleted = data_store.delete_userapp(stack_id)

    return '', 200


def rename_userapp(stack_id, name):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != namespace:
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
    claims = jwt.safe_decode(token)
    namespace = claims.username

    # TODO: Check if user already has an instance of this app
    # TODO: If it exists, start it up and return
    # TODO: If it does not exist, create, start, then return


    return '', 200


def start_stack(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    # Lookup userapp using the id
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != namespace:
        return 'Only the owner may launch a userapp', 403

    # TODO: Create Deployment in Kubernetes

    # TODO: Mark userapp as STARTING, then return

    # TODO: Eventually, Pod is Running and event watchers
    #    should update userapp state to STARTED

    return '', 202


def stop_stack(stack_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    namespace = claims.username

    # Lookup userapp using the id
    userapp = data_store.retrieve_userapp_by_id(stack_id)

    # Verify that this user is the owner
    if userapp['creator'] != namespace:
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
    namespace = claims.username

    configs = []
    all_appspecs = data_store.fetch_all_appspecs_for_user(namespace)
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


