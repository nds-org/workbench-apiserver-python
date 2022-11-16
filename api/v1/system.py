import connexion
import logging

from pkg import config
from yaml import load

import git

logger = logging.getLogger('api.v1.system')

# First fetch to /api/v1/version will cache this
config.VERSION_NUMBER = None

def get_version():
    if config.VERSION_HASH is None:
        try:
            repo = git.Repo(search_parent_directories=True)
            config.VERSION_HASH = repo.head.object.hexsha
        except:
            pass

    if config.VERSION_NUMBER is None:
        try:
            with open(config.SWAGGER_URL) as f:
                yaml_str = f.read()
                yaml_spec = load(yaml_str)
                config.VERSION_NUMBER = yaml_spec['info']['version']
        except:
            pass

    return {'version': config.VERSION_NUMBER, 'hash': config.VERSION_HASH}, 200

