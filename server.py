import json
import logging
import os

import connexion
from flask import request
from flask_cors import CORS
from flask_sock import Sock

from pkg import config, kube

from pkg.openapi.resolver import OperationResolver


logger = logging.getLogger("server")

sock = Sock()


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
    app.app.config['SOCK_SERVER_OPTIONS'] = {'ping_interval': config.SOCK_PING_INTERVAL,
                                             'max_message_size': config.SOCK_MAX_MESSAGE_SIZE}

    sock = Sock(app.app)

    # example: /api/console?namespace=lambert8&ssid=svwk8l-toolmanager
    @sock.route('/api/console')
    def console(ws):
        namespace = request.args.get('namespace')
        ssid = request.args.get('ssid')

        logger.debug(f'Connecting to: {namespace}/{ssid}')
        kube.open_exec_userapp_interactive(user=namespace, ssid=ssid, ws=ws)


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

