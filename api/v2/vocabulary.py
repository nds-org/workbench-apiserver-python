import logging

from helper import etcdClient
from bson import ObjectId
from pkg.mongo import get_mongo_client, parse_json
from pkg import config

import json
import connexion


# TODO: v2
VOCABULARIES_COLLECTION_NAME = 'vocabularies'



def list_vocabularies():
    # TODO: handle filter params
    #if catalog is not None and catalog != '':
    #    docs = list(db[APP_SPECS_COLLECTION_NAME].find({ 'catalog': catalog }))
    #    logger.debug(docs)
    #    return docs, 200

    mongo_client = get_mongo_client()
    with mongo_client:
        db = mongo_client['workbench']
        cursor = db[VOCABULARIES_COLLECTION_NAME].find({})
        docs = list(cursor)
        return parse_json(docs), 200
    return { 'error': 'Failed to connect to MongoDB' }, 500


def create_vocabulary(vocabulary):
    mongo_client = get_mongo_client()
    with mongo_client:
        db = mongo_client['workbench']
        record = db[VOCABULARIES_COLLECTION_NAME].insert_one(vocabulary)
        vocabulary['_id'] = str(record.inserted_id)
        return parse_json(vocabulary), 201
    return { 'error': 'Failed to connect to MongoDB' }, 500


def get_vocabulary_by_name(vocab_name):
    mongo_client = get_mongo_client()
    with mongo_client:
        db = mongo_client['workbench']
        selector = { 'name': ObjectId(vocab_name) }
        target_service = db[VOCABULARIES_COLLECTION_NAME].find_one(selector)
        return parse_json(target_service), 200
    return { 'error': 'Failed to connect to MongoDB' }, 500


def update_vocabulary(vocab_name, vocabulary):
    mongo_client = get_mongo_client()
    with mongo_client:
        db = mongo_client['workbench']
        selector = { 'name': ObjectId(vocab_name) }
        db[VOCABULARIES_COLLECTION_NAME].replace_one(selector, vocabulary)
        return parse_json(vocabulary), 200
    return { 'error': 'Failed to connect to MongoDB' }, 500


def delete_vocabulary(vocab_name):
    mongo_client = get_mongo_client()
    with mongo_client:
        db = mongo_client['workbench']
        selector = { 'name': ObjectId(vocab_name) }
        db[VOCABULARIES_COLLECTION_NAME].remove(selector)
        return 204
    return { 'error': 'Failed to connect to MongoDB' }, 500






VOCABULARY_SUFFIX = '/vocabularies'
VOCABULARY_BASE_PATH = config.ETCD_BASE_PATH + VOCABULARY_SUFFIX


def search():
    args = connexion.request.args
    param = args.get('services')
    logging.info("Get configs with service - "+param)

    #services = []
    # if catalog == 'system':
    #    services = etcdClient.getSystemServices()
    # elif catalog == 'user':
    #    services = etcdClient.getUserServices()
    # else:  # catalog == all or others
    #    services = etcdClient.getAllServices()

    return param
