import logging

import json
import connexion

from helper import etcdClient
from pkg.jwt import WBJWT


def search():
    args = connexion.request.args
    param = args.get('services')
    logging.info("Get auth - "+param)

    return param


def post():
    reqJSON = connexion.request.json
    username = reqJSON['username']
    password = reqJSON['password']
    # id is username??
    id = username

    if etcdClient.checkPassword(username, password):
        token = {"token": WBJWT.encode(username, id)}
        return token

    return ''
