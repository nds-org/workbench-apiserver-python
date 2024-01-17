#!/usr/bin/env python3

import os
import sys
import logging
from datetime import datetime, timezone

from kubernetes import client, config


logger = logging.getLogger('scale-down')

# TODO: Pull these from pkg/config.py?
TARGET_LABEL_NAME = os.getenv('TARGET_LABEL_NAME', 'manager')
TARGET_LABEL_VALUE = os.getenv('TARGET_LABEL_VALUE', 'workbench')

NAMESPACE = os.getenv('NAMESPACE', 'cheesehub')

DEBUG = os.getenv('DEBUG', 'false').lower() in 'true'
FORCE = os.getenv('FORCE', 'false').lower() in 'true'

if DEBUG:
    logging.basicConfig(
        format='%(asctime)-15s %(message)s', level=logging.DEBUG)
else:
    logging.basicConfig(
        format='%(asctime)-15s %(message)s', level=logging.INFO)

# TODO: Pull this from api/v1/app_specs.py?

# Configs can be set in Configuration class directly or using helper utility
config.load_incluster_config()

#
def scale_down_deployments(namespace=NAMESPACE):
    v1apps = client.AppsV1Api()

    # Check all Pods, note the Age
    v1 = client.CoreV1Api()
    logger.info('Listing pods with their age...')
    pods = v1.list_namespaced_pod(namespace=namespace, watch=False)

    targets = []
    for p in pods.items:
        if TARGET_LABEL_NAME in p.metadata.labels and p.metadata.labels[TARGET_LABEL_NAME] == TARGET_LABEL_VALUE:
            #print("Creation Timestamp: %s" % p.metadata.creation_timestamp)
            tdelta = datetime.now(timezone.utc) - p.metadata.creation_timestamp

            if tdelta.days > 10:
                #print("The creation date is older than 10 days")
                logger.info('>> Scaling down Pod=%s' % p.metadata.name)
                deployment_name = '%s-%s-%s' % (p.metadata.labels['user'], p.metadata.labels['workbench-app'], p.metadata.labels['workbench-svc'])

                # TODO verify that deployment exists?
                #v1apps.read_namespaced_deployment(name=deployment_name, namespace=namespace)

                # Scale down deployment to 0
                scale_result = v1apps.patch_namespaced_deployment_scale(namespace=namespace, name=deployment_name,
                                                                        body={'spec': {'replicas': 0}})
                logger.info('>> Scaled down Deployment=%s, Result: %s' % (deployment_name, scale_result))
            elif DEBUG:
                logger.info('Skipping Pod=%s - The creation date is not older than 10 days' % p.metadata.name)
        elif DEBUG:
            logger.debug('Skipping Pod=%s - Missing required label: %s' % (p.metadata.name, p.metadata.labels))

        targets.append(p)
        # TODO: check Pod age, scale down if older than some period
        #print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))


    # Loop over targets, scale down each deployment
    #for d in targets:
    #    v1apps.patch_namespaced_deployment_scale(name=d.metadata.name, namespace=NAMESPACE, body=)


def get_deployment(name, namespace):
    try:
        return client.AppsV1Api().read_namespaced_deployment(name=name, namespace=namespace)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            logger.error("Error reading deployment resource: %s" % str(exc))
            raise exc


def patch_scale_deployment(deployment_name, namespace, replicas) -> bool:
    # No-op if we can't find the deployment
    deployment = get_deployment(name=deployment_name, namespace=namespace)
    logger.info(f'Patching {deployment_name} to replicas={str(replicas)}')
    if deployment is None:
        # TODO: Raise an error here?
        logger.error("Failed to find deployment: " + str(deployment_name))
        return False

    # No-op if we already have our desired number of replicas
    current_repl = deployment.spec.replicas
    if current_repl == replicas:
        logger.debug("No-op for setting replicas number: %d -> %d" % (current_repl, replicas))
        return False

    # Query number of replicas
    result = client.AppsV1Api().patch_namespaced_deployment_scale(namespace=namespace, name=deployment_name,
                                                                  body={'spec': {'replicas': replicas}})
    logger.debug("Patch Result: " + str(result))
    return result


if __name__ == '__main__':
    scale_down_deployments()
