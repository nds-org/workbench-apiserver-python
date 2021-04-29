import logging

import json
import connexion

from helper import etcdClient
from pkg import validate


def search():
    token_user_id = connexion.context['token_info']['user']

    return token_user_id


def get(account_id):
    #token_user_id = connexion.context['token_info']['user']

    account_info = etcdClient.getAccountInfo(account_id)

    if account_info == '':
        return '', 204
    else:
        return account_info, 200


def put(account_id):
    # if validate.validate_account_info(account_info):
    #    etcdClient.setAccountInfo(account_info)
    #    return True, 200
    # else:
    #    return '', 204
    print(connexion.request.json)
    etcdClient.setAccountInfo(connexion.request.json)


def delete(account_id):
    return etcdClient.deleteAccountInfo(account_id)
