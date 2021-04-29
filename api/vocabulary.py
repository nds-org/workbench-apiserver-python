import logging

from helper import etcdClient

import json
import connexion


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
