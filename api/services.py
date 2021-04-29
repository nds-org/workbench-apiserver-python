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

    if 'x_access_token' in connexion.request.headers:
        token = connexion.request.headers['X-Access-Token']
        print(token)
    print("---- start ----")
    print(connexion.request.headers)
    print("==== end ====")

    return services, 200


def get(service_id):
    service = etcdClient.getServiceWithId(service_id)

    if service is '':
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
