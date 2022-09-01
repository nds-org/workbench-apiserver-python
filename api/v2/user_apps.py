import os
import uuid
from kubernetes.client import ApiException, ApiValueError

import pkg.kube
from pkg import kube, config

import logging

logger = logging.getLogger('user_apps')

# TODO: v2
USER_APPS_COLLECTION_NAME = 'user_apps'


# TODO: Pattern param?
def generate_random(digits=16, pattern=''):
    return os.urandom(digits)


def list_stacks(user, token_info):
    namespace = pkg.kube.get_resource_namespace(user)

    try:
        userapps = kube.list_custom_user_apps(namespace)
        return userapps, 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to list custom userapp resources: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to list custom userapp resources: " + str(err))


    # TODO: handle filter params
    #if catalog is not None and catalog != '':
    #    docs = list(db[APP_SPECS_COLLECTION_NAME].find({ 'catalog': catalog }))
    #    logger.debug(docs)
    #    return docs, 200

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    cursor = db[USER_APPS_COLLECTION_NAME].find({})
    #    docs = list(cursor)
    #    return parse_json(docs), 200
    return {'error': 'An unknown error has occurred'}, 500


def create_stack(user, token_info, stack):
    # generate "unique" id
    sid = stack['id'] = str(uuid.uuid1())

    # TODO: Build up full request parameters
    namespace = pkg.kube.get_resource_namespace(user)

    app_name = pkg.kube.get_resource_name(user, sid)

    service_ports = {
        'http': 80,
        'https': 443
    }
    labels = {
        'manager': 'workbench',
        'user': user,
        'workbench-app': sid
    }

    # Create cluster resources
    service = kube.create_service(service_name=app_name, service_ports=service_ports,
                                  namespace=namespace, labels=labels)

    logger.debug("Service created: " + str(service))
    for port in service_ports:
        ingress_name = pkg.kube.get_resource_name(user, app_name, port)
        ingress = kube.create_ingress(ingress_name=ingress_name, host='%s.%s' % (ingress_name, config.DOMAIN),
                                      path='/', pathType='Prefix', namespace=namespace,
                                      service_name=service.metadata.name, service_port=port)
    configmap = kube.create_configmap(configmap_name=app_name, labels=labels,
                                      namespace=namespace, configmap_data={
                                          # TODO: insert per-app env here
                                      })

    #   "busybox" -> { name, configmap, image, lifecycle, ports, command }
    containers = []
    for svc in stack['services']:
        appspec_key = svc['service']
        try:
            logger.debug("Fetching app spec: %s" % appspec_key)
            appspec = kube.retrieve_custom_app_spec(appspec_key)
        except ApiException as err:
            logger.error("Failed to lookup AppSpec resource: " + str(err))
            return {'error': 'AppSpec resource was not found: ' + appspec_key}, 400
        container = {
            "name": appspec_key,
            "configmap": configmap.metadata.name,
            "image": svc['imageTag'] if svc['imageTag'] else appspec['image']['name'],
            "ports": svc['ports'] if 'ports' in svc else {},
            "lifecycle": None,
            "command": svc['command'] if 'command' in svc else appspec['command']
        }
        containers.append(container)
    deployment = kube.create_deployment(deployment_name=app_name, replicas=0,
                                        namespace=namespace, labels=labels,
                                        containers=containers)

    # Add accounting info to userdata configmap
    logger.debug("Creating custom userapp: " + str(stack))
    try:
        return kube.create_custom_user_app(stack, namespace), 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to create custom userapp resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to create custom userapp resource: " + str(err))

    # mongo_client = get_mongo_client()
    # with mongo_client:
    #    db = mongo_client['workbench']
    #    record = db[USER_APPS_COLLECTION_NAME].insert_one(stack)
    #    stack['_id'] = str(record.inserted_id)
    #    return parse_json(stack), 201
    return {'error': 'An unknown error has occurred'}, 500


def get_stack_by_id(user, token_info, stack_id):
    namespace = pkg.kube.get_resource_namespace(user)

    name = pkg.kube.get_resource_name(user, stack_id)

    try:
        return kube.retrieve_custom_user_app(name, namespace), 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to retrieve custom userapp resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to retrieve custom userapp resource: " + str(err))


    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    selector = { '_id': ObjectId(stack_id) }
    #    target_service = db[USER_APPS_COLLECTION_NAME].find_one(selector)
    #    return parse_json(target_service), 200
    return {'error': 'An unknown error has occurred'}, 500


def update_stack(user, token_info, stack_id, stack):
    namespace = pkg.kube.get_resource_namespace(user)

    name = pkg.kube.get_resource_name(user, stack_id)

    try:
        return kube.replace_custom_user_app(name, namespace, stack), 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to replace custom userapp resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to replace custom userapp resource: " + str(err))


    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    selector = { '_id': ObjectId(stack_id) }
    #    db[USER_APPS_COLLECTION_NAME].replace_one(selector, stack)
    #    return parse_json(stack), 200
    return {'error': 'An unknown error has occurred'}, 500


def delete_stack(user, token_info, stack_id):
    namespace = pkg.kube.get_resource_namespace(user)

    name = pkg.kube.get_resource_name(user, stack_id)

    try:
        return kube.delete_custom_user_app(name, namespace), 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to delete custom userapp resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to delete custom userapp resource: " + str(err))

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    selector = { '_id': ObjectId(stack_id) }
    #    db[USER_APPS_COLLECTION_NAME].remove(selector)
    #    return 204
    return {'error': 'An unknown error has occurred'}, 500


def start_stack(user, token_info, stack_id):
    namespace = pkg.kube.get_resource_namespace(user)

    name = pkg.kube.get_resource_name(user, stack_id)

    try:
        return kube.patch_scale_deployment(deployment_name=name, namespace=namespace, replicas=1), 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to start custom userapp resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to start custom userapp resource: " + str(err))


    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    selector = { '_id': ObjectId(stack_id), 'status': 'started' }
    #    db[USER_APPS_COLLECTION_NAME].replace_one(selector, stack)
    #    return parse_json(stack), 200
    return {'error': 'An unknown error has occurred'}, 500


def stop_stack(user, token_info, stack_id):
    namespace = pkg.kube.get_resource_namespace(user)

    name = pkg.kube.get_resource_name(user, stack_id)

    try:
        return kube.patch_scale_deployment(name, namespace, 0), 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to stop custom userapp resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to stop custom userapp resource: " + str(err))

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    selector = { '_id': ObjectId(stack_id), 'status': 'stopped' }
    #    db[USER_APPS_COLLECTION_NAME].replace_one(selector, stack)
    #    return parse_json(stack), 200
    return {'error': 'An unknown error has occurred'}, 500
