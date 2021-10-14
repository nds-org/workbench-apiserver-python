import logging

import jwt
import datetime
import os

from pkg import config


class WBJWT:

    @staticmethod
    def encode(id, user):
        iat = datetime.datetime.utcnow()
        timeout = datetime.timedelta(minutes=config.JWT_EXP_DELTA_MINS)
        exp = iat + timeout
        server = os.uname()[1]

        payload = {
            "exp": exp,
            "id": id,
            "iat": iat,
            "server": server,
            "user": user
        }

        return jwt.encode(payload, config.JWT_SECRET, config.JWT_ALGORITHM)

    @staticmethod
    def decode(jwt_token):
        return jwt.decode(jwt_token, config.JWT_SECRET, config.JWT_ALGORITHM)
