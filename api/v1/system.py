import logging

from pkg import config

logger = logging.getLogger('api.v1.system')

def get_version():
    return {
        'name': config.VERSION_NAME,
        'version': config.VERSION_NUMBER,
        'hash': config.VERSION_HASH,
        'branch': config.VERSION_BRANCH,
        'buildnumber': config.VERSION_BUILDNUMBER,
    }, 200

