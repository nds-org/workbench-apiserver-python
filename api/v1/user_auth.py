import connexion

import pkg

import logging

logger = logging.getLogger('api.v1.user_auth')

def post_authenticate():
    reqJSON = connexion.request.json
    username = reqJSON['username']
    password = reqJSON['password']
    print(username, password)

    if etcdClient.checkPassword(username, password):
        token = {"token": pkg.jwt.encode(username)}
        return token, 200
    else:
        return '', 401


def delete_authenticate():
    return '', 501


def refresh_token():
    return '', 501


def check_token():
    return '', 501

