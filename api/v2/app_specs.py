import logging

from kubernetes.client import ApiValueError, ApiException


from bson import ObjectId, json_util


import json
import connexion

from pkg import config, kube
from pymongo import MongoClient

import logging

logger = logging.getLogger('app_specs')

# TODO: v2
APP_SPECS_COLLECTION_NAME = 'application_specs'


def list_services(catalog=''):
    try:
        appspecs = kube.list_custom_app_specs()
        return appspecs, 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to list custom appspec resources: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to list custom appspec resources: " + str(err))

    # TODO: handle filter params
    #if catalog is not None and catalog != '':
    #    docs = list(db[APP_SPECS_COLLECTION_NAME].find({ 'catalog': catalog }))
    #    logger.debug(docs)
    #    return docs, 200

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    cursor = db[APP_SPECS_COLLECTION_NAME].find()
    #    docs = list(cursor)
    #    return parse_json(docs), 200
    #return { 'error': 'Failed to connect to MongoDB' }, 500
    return {'error': 'An unknown error has occurred'}, 500


def create_service(service):
    try:
        appspec = kube.create_custom_app_spec(service)
        return appspec, 201
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to create custom appspec resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to create custom appspec resource: " + str(err))

    return {'error': 'An unknown error has occurred'}, 500

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    record = db[APP_SPECS_COLLECTION_NAME].insert_one(service)
    #    service['_id'] = str(record.inserted_id)
    #    return parse_json(service), 201
    #return { 'error': 'Failed to connect to MongoDB' }, 500


def get_service_by_id(service_id):
    try:
        appspec = kube.retrieve_custom_app_spec(service_id)
        return appspec, 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to retrieve custom appspec resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to retrieve custom appspec resource: " + str(err))

    return {'error': 'An unknown error has occurred'}, 500

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    target_service = db[APP_SPECS_COLLECTION_NAME].find_one({ '_id': ObjectId(service_id) })
    #    return parse_json(target_service), 200
    #return { 'error': 'Failed to connect to MongoDB' }, 500


def update_service(service_id, service):
    try:
        appspec = kube.replace_custom_app_spec(service_id, service)
        return appspec, 200
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to replace custom appspec resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to replace custom appspec resource: " + str(err))

    return {'error': 'An unknown error has occurred'}, 500

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    db[APP_SPECS_COLLECTION_NAME].replace_one({ '_id': ObjectId(service_id) }, service)
    #    return parse_json(service), 200
    #return { 'error': 'Failed to connect to MongoDB' }, 500


def delete_service(service_id):
    try:
        appspec = kube.delete_custom_app_spec(service_id)
        return 204
    except ApiValueError as err:
        logger.error("ApiValueError: Failed to delete custom appspec resource: " + str(err))
    except ApiException as err:
        logger.error("ApiException: Failed to delete custom appspec resource: " + str(err))

    return {'error': 'An unknown error has occurred'}, 500

    #mongo_client = get_mongo_client()
    #with mongo_client:
    #    db = mongo_client['workbench']
    #    db[APP_SPECS_COLLECTION_NAME].remove({ '_id': ObjectId(service_id) })
    #    return 204
    #return { 'error': 'Failed to connect to MongoDB' }, 500








SERVICES_SUFFIX = '/services'
SYS_CATALOG_BASE_PATH = config.ETCD_BASE_PATH + SERVICES_SUFFIX


#@staticmethod
#def USER_CATALOG_PATH(username):
#    return USER_BASE_PATH(username) + SERVICES_SUFFIX


def run():
    args = connexion.request.cookies   #.args
    catalog = args.get('catalog')
    logging.info("Get services with catalog - "+catalog)

    services = []
    #if catalog == 'system':
        # services = etcdClient.getSystemServices()
    #elif catalog == 'user':
        # services = etcdClient.getUserServices()
    #else:  # catalog == all or others
        # services = etcdClient.getAllServices()

    if 'x_access_token' in connexion.request.headers:
        token = connexion.request.headers['X-Access-Token']
        print(token)
    print("---- start ----")
    print(connexion.request.headers)
    print("==== end ====")

    return services, 200


def get(service_id):
    service = '' # etcdClient.getServiceWithId(service_id)

    if service == '':
        return '', 204
    else:
        return service, 200


def post():
    service = connexion.request.json
    print(service)

    return "POST testing - "


def put(service_id):
    return "PUT testing "+service_id


def delete(service_id):
    return "DELETE testing "+service_id
