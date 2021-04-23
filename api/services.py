import logging

from helper import etcdClient

import json
import connexion


def search():
    args = connexion.request.args
    catalog = args.get('catalog')
    logging.info("Get services with catalog - "+catalog)

    services = []
    if catalog == 'system':
        services = etcdClient.getSystemServices()
    elif catalog == 'user':
        services = etcdClient.getUserServices()
    else:  # catalog == all or others
        services = etcdClient.getAllServices()

    return services


def get(service_id):
    service = etcdClient.getServiceWithId(service_id)
    return service


def post():
    service = connexion.request.json
    print(service)

    return "POST testing - "


def put(service_id):
    return "PUT testing "+service_id


def delete(service_id):
    return "DELETE testing "+service_id
