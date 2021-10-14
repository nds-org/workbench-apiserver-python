import connexion
import logging

logger = logging.getLogger('system')


def get_version():
    logger.debug(connexion.context)
    return "v2.0, bay-beeeee"
