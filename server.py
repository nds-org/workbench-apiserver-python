import logging

import connexion
from flask_cors import CORS

from pkg import config, kube

from pkg.openapi.resolver import OperationResolver


logger = logging.getLogger("server")

if __name__ == '__main__':
    debug = config.DEBUG

    if debug:
        logging.basicConfig(
            format='%(asctime)-15s %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(asctime)-15s %(message)s', level=logging.INFO)

    kube.initialize()

    app = connexion.FlaskApp(__name__, debug=debug)

    if str.startswith(config.SWAGGER_URL, "http"):
        # fetch remote openapi spec
        app.add_api(config.download_remote_swagger_to_temp_file(),
                    # resolver=DebugRestyResolver(),
                    resolver=OperationResolver('api'),
                    arguments={'title': 'PYNDSLABS.V1'}, resolver_error=501,
                    strict_validation=True)
    else:
        # use local openapi spec
        app.add_api(config.SWAGGER_URL,
                    # resolver=DebugRestyResolver(),
                    resolver=OperationResolver('api'),
                    arguments={'title': 'PYNDSLABS.V1'}, resolver_error=501,
                    strict_validation=True)

    CORS(app.app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

    watcher = kube.KubeEventWatcher()
    try:
        app.run(port=5000, host='0.0.0.0', server='flask', debug=debug)
    finally:
        watcher.close()
