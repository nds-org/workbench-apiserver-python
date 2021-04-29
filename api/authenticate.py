import logging

import json
import connexion
import datetime
import os

from werkzeug.exceptions import Unauthorized
from jose import JWTError, jwt
import six

from helper import etcdClient

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_MINS = 3


def search():
    logging.info("Token info - "+connexion.context['token_info'])

    return param


def post():
    reqJSON = connexion.request.json
    username = reqJSON['username']
    password = reqJSON['password']
    print(username, password)

    if etcdClient.checkPassword(username, password):
        token = {"token": generate_token(username)}
        return token

    #token = generate_token(username)
    # return {"token": token}


def delete():
    print(connexion.request.auth)
    return True


def generate_token(user_id):
    iat = datetime.datetime.utcnow()
    timeout = datetime.timedelta(minutes=JWT_EXP_DELTA_MINS)
    exp = iat + timeout
    server = os.uname()[1]

    payload = {
        "exp": exp,
        "id": user_id,
        "iat": iat,
        "server": server,
        "user": user_id
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        six.raise_from(Unauthorized, e)
