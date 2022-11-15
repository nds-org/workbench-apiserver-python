import connexion
import logging

from pkg import config
from yaml import load

logger = logging.getLogger('api.v1.system')

# First fetch to /api/v1/version will cache this
config.VERSION_NUMBER = None


def get_version():
    if config.VERSION_NUMBER is None:
        try:
            with open(config.SWAGGER_URL) as f:
                yaml_str = f.read()
                yaml_spec = load(yaml_str)
                config.VERSION_NUMBER = yaml_spec['info']['version']
                return config.VERSION_NUMBER, 200
        except:
            return 'unknown', 404
    else:
        return config.VERSION_NUMBER, 200

