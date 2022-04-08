import connexion
import logging

logger = logging.getLogger('api.v1.system')


def get_version():
    return "2.0.0-alpha.1"

