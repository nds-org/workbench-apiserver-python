import logging

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
    watcher = kube.KubeEventWatcher()

    app = connexion.FlaskApp(__name__, debug=debug)
    app.app.config['SOCK_SERVER_OPTIONS'] = {'ping_interval': config.SOCK_PING_INTERVAL,
                                             'max_message_size': config.SOCK_MAX_MESSAGE_SIZE}

    sock = Sock(app.app)


    # example: /api/console?namespace=lambert8&ssid=svwk8l-toolmanager
    @sock.route('/api/console')
    def console_exec(ws):
        namespace = kube.get_username(request.args.get('namespace'))
        ssid = request.args.get('ssid')

        logger.debug(f'Connecting to console: {namespace}/{ssid}')
        kube.open_exec_userapp_interactive(user=namespace, ssid=ssid, ws=ws)

    # TODO: async events API
    # example: /api/events?namespace=lambert8

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

    # TODO: CORS
    CORS(app.app, resources={r"/api/*": {"origins": "*"}})

    try:
        logger.info(f'Connecting to MongoDB: {config.MONGO_URI} ({config.MONGO_DB})')
        app.run(port=5000, host='0.0.0.0', server='flask', debug=debug)
    finally:
        watcher.close()

