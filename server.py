import logging

import connexion
# from brapiresolver import BrapiResolver

from pkg import config, kube

#from pkg.mongo import db

logger = logging.getLogger("server")


class DebugRestyResolver(connexion.RestyResolver):
    def resolve_operation_id(self, operation):
        result = super().resolve_operation_id(operation)
        logger.debug(f"{operation} == {result}")
        return result


if __name__ == '__main__':
    debug = True

    if config.KUBE_WORKBENCH_NAMESPACE is not None and config.KUBE_WORKBENCH_NAMESPACE != '':
        logger.debug("Starting in single-namespace mode: " + config.KUBE_WORKBENCH_NAMESPACE)
        try:
            kube.create_namespace(config.KUBE_WORKBENCH_NAMESPACE)
        except Exception as err:
            logger.warning("Failed to create base namespace %s: %s" % (config.KUBE_WORKBENCH_NAMESPACE, err))

        if config.KUBE_WORKBENCH_RESOURCE_PREFIX:
            logger.debug("Using resource prefix: " + config.KUBE_WORKBENCH_RESOURCE_PREFIX)
    else:
        logger.debug("Starting in multi-namespace mode")

    if debug:
        logging.basicConfig(
            format='%(asctime)-15s %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(asctime)-15s %(message)s', level=logging.INFO)

    app = connexion.FlaskApp(__name__, debug=debug)

    if str.startswith(config.SWAGGER_URL, "http"):
        # fetch remote swagger
        app.add_api(config.download_remote_swagger_to_temp_file(),
                    resolver=DebugRestyResolver('api.v2'),
                    arguments={'title': 'PYNDSLABS.V2'}, resolver_error=501)
    else:
        # use local swagger
        app.add_api(config.SWAGGER_URL,
                    resolver=DebugRestyResolver('api.v2'),
                    arguments={'title': 'PYNDSLABS.V2'}, resolver_error=501)

    app.run(port=5000, host='0.0.0.0', server='flask', debug=debug)
