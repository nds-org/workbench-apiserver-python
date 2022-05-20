import json
import logging
import logging.config
import string
import random
import time

import requests
import threading

from kubernetes import watch, client, config as kubeconfig
from kubernetes.client import ApiException
from requests import HTTPError

from pkg import config
from pkg.auth import keycloak
from pkg.config import KUBE_WORKBENCH_NAMESPACE, KUBE_WORKBENCH_RESOURCE_PREFIX
from pkg.db.datastore import data_store
from pkg.exceptions import AppSpecNotFoundError

CRD_GROUP_NAME = "ndslabs.org"
CRD_VERSION_V1 = "v1"
CRD_APPSPECS_PLURAL = "workbenchappspecs"
CRD_USERAPPS_PLURAL = "workbenchuserapps"
CRD_APPSPECS_KIND = "WorkbenchAppSpec"
CRD_USERAPPS_KIND = "WorkbenchUserApp"

logger = logging.getLogger('kube')

BASE_URL = 'http://localhost:5000'

kubeconfig.load_kube_config()
custom = client.CustomObjectsApi()

client.api_client.rest.logger.setLevel(logging.WARNING)


# TODO: V2 - watch custom resources and react accordingly
# watched_namespaces = ["test"]
# for namespace in watched_namespaces:
#    count = 10
#    w = watch.Watch()
#    for event in w.stream(custom.list_namespaced_custom_object,
#                          group=CRD_GROUP_NAME,
#                          version=CRD_VERSION_V1,
#                          namespace=namespace,
#                          plural=CRD_USERAPPS_PLURAL,
#                          _request_timeout=60):
#        print("Event: %s %s" % (event['type'], event['object']['metadata']['name']))
#        count -= 1
#        time.sleep(10)
#        if not count:
#            w.stop()

def determine_new_endpoints(userapp_id, username, service_key, conditions):
    # logger.debug('Pod Conditions: %s' % conditions)
    service_endpoints = []
    if conditions is not None:
        # Examine Ready condition and assign endpoints if it is True
        is_ready = [x.status for x in conditions if x.type == 'Ready']
        # logger.debug('Is Ready: %s' % is_ready)
        if len(is_ready) != 1:
            logger.error('Sanity check: is_ready not found! Skipping..')
            return service_endpoints

        app_spec = data_store.retrieve_system_appspec_by_key(spec_key=service_key)
        if app_spec is None:
            app_spec = data_store.retrieve_user_appspec_by_key(spec_key=service_key, username=username)

        if app_spec is None:
            logger.warning('Skipping endpoint update. Spec not found anywhere: %s' % service_key)
        else:
            logger.debug('App spec found: ' + app_spec['key'])
            service_ports = app_spec['ports'] if 'ports' in app_spec else []
            logger.debug('Checking if container is ready... %s' % is_ready)
            if is_ready[0] == 'True':
                logger.debug('Container ready, creating endpoints...')

                service_endpoints = []
                for p in service_ports:
                    # Only specs that are supposed to be exposed externally
                    if app_spec['access'] != 'external':
                        logger.debug('Skipping internal endpoint: ' + app_spec['key'])
                        continue

                    # Grab what we need from the app_spec to point at the ingress rule for this app
                    protocol = p['protocol'] if 'protocol' in p else 'tcp'
                    path = p['path'] if 'path' in p else '/'
                    port = p['port'] if 'port' in p else ''
                    nodePort = p['nodePort'] if 'nodePort' in p else ''

                    # Port is not typically used (possibly in dev, but even then probably not)
                    actual_port = nodePort if nodePort else port if port else ''

                    # Use username+appId+portnumber for ingress host
                    prefix = get_resource_name(userapp_id, service_key)

                    # TODO: Handle multiple ports? e.g. rabbitmq 5672 + 15672?
                    #  if actual_port is '' else get_resource_name(username, userapp_id, str(actual_port))

                    host = '%s.%s' % (prefix, config.DOMAIN)

                    endpoint = {
                        'host': host,
                        'protocol': protocol,
                        'path': path,
                        # 'port': ':',       # unused
                        # 'nodePort': ':',   # unused
                        'url': '%s://%s%s' % (protocol, host, path),
                    }

                    logger.debug('Adding endpoint: %s' % endpoint)

                    service_endpoints.append(endpoint)
            else:
                # If Pod not ready, don't expose endpoints yet
                logger.debug('Container not yet ready, skipping endpoint creation...')
                service_endpoints = []

    return service_endpoints

def determine_new_status(type, phase):
    service_status = phase  # default is no phase change

    # TODO: Update stack service phase according to phase/type
    if phase == 'Pending':  # TODO: initial scheduling phase
        service_status = 'initializing'
    elif phase == 'Error':  # TODO: errors at startup/runtime
        service_status = 'error'
    elif phase == 'Running' and type != 'DELETED':  # TODO: errors at startup/runtime
        service_status = 'running'
    elif type == 'ADDED':  # TODO: 'starting' incremental phase updates
        service_status = 'created'
    elif type == 'DELETED':  # TODO: 'stopping' incremental phase updates
        service_status = 'stopped'
    elif type == 'MODIFIED':  # TODO: granular incremental phase updates (conditions?)
        service_status = 'starting'

    return service_status


def write_status_and_endpoints(userapp_id, username, service_key, service_status, service_endpoints):
    userapp = data_store.retrieve_userapp_by_id(userapp_id=userapp_id, username=username)
    if userapp is not None:
        services = userapp['services']
        for service in services:
            if service['service'] == service_key:
                ssid = '%s-%s' % (userapp_id, service_key)
                logger.debug('%s -> %s (owned by %s)' % (ssid, service_status, username))

                service['status'] = service_status
                service['endpoints'] = service_endpoints

        # if all services running, set whole app state to running
        running_services = [x['service'] for x in services if x['status'] == 'running']
        if len(running_services) == len(services):
            userapp['status'] = 'running'
            logger.debug('%s -> %s (owned by %s)' % (userapp_id, 'running', username))

        # if all services stopped, set whole app state to stopped
        stopped_services = [x['service'] for x in services if x['status'] == 'stopped']
        if len(stopped_services) == len(services):
            userapp['status'] = 'stopped'
            logger.debug('%s -> %s (owned by %s)' % (userapp_id, 'stopped', username))

        # Assume success?
        result = data_store.update_userapp(userapp)
    else:
        logger.warning('Unable to update status and endpoints: Userapp not found: %s %s' % (username, userapp_id))


class KubeEventWatcher:

    def __init__(self):
        self.logger = logging.getLogger('kube-event-watcher')
        self.thread = threading.Thread(target=self.run, name='kube-event-watcher', daemon=True)
        self.stream = None
        logger.info('Starting Kube event watcher')
        self.thread.start()

    def run(self):
        w = watch.Watch()
        v1 = client.CoreV1Api()
        appsv1 = client.AppsV1Api()

        # Resource version is used to keep track of stream progress (in case of resume)
        resource_version = ""

        # Ignore kube-system namespace
        # TODO: Parameterize this?
        ignored_namespaces = ['kube-system']

        # Include workbench app labels
        # Example:      'labels': {'manager': 'workbench',
        #                          'pod-template-hash': '977967b76',
        #                          'user': 'test',
        #                          'workbench-app': 's00402'}
        # TODO: Parameterize this?
        required_labels = {
            'manager': 'workbench'
        }

        while True:
            time.sleep(1)
            try:
                # Resource version is used to keep track of stream progress (in case of resume)
                self.stream = w.stream(func=v1.list_pod_for_all_namespaces, resource_version=resource_version, timeout_seconds=0)
                resource_version = v1.list_pod_for_all_namespaces().metadata.resource_version

                # Parse events in the stream for Pod phase updates
                for event in self.stream:
                    # Skip Pods in ignored namespaces
                    if event['object'].metadata.namespace in ignored_namespaces:
                        continue

                    # logger.debug('Received pod event: %s' % str(event['object'].phase))

                    # Examine labels, ignore if not workbench app
                    #logger.debug('Event recv\'d: %s' % event)
                    labels = event['object'].metadata.labels

                    missing_labels = [x for x in required_labels if x not in labels]
                    if len(missing_labels) > 0:
                        self.logger.warning('WARNING: Skipping due to missing required label(s): ' + missing_labels)
                        continue

                    # TODO: lookup associated userapp using resource name
                    name = event['object'].metadata.name

                    # Parse name into userapp_id + ssid
                    segments = name.split('-')
                    if len(segments) < 4:
                        self.logger.warning('WARNING: Invalid number of segments -  PodName=%s' % name)
                        continue

                    userapp_id = segments[0]
                    username = labels['user']
                    service_key = '-'.join(segments[1:-2])

                    type = event['type']
                    phase = event['object'].status.phase
                    conditions = event['object'].status.conditions

                    service_endpoints = determine_new_endpoints(userapp_id, username, service_key, conditions)

                    service_status = determine_new_status(type, phase)

                    write_status_and_endpoints(userapp_id, username, service_key, service_status, service_endpoints)

                    logger.debug(
                        'UserappId=%s  ServiceKey=%s  type=%s  phase=%s  ->  status=%s' % (userapp_id, service_key, type, phase, service_status))
            except ApiException as e:
                logger.error("Connection to kube API failed: " + str(e))
                time.sleep(2)
                continue

    def is_alive(self):
        return self.thread.is_alive()

    def close(self):
        if self.thread is None:
            return
        if self.thread.is_alive():
            self.thread.join(timeout=3)
            self.thread = None


def generate_random_password(length=16):
    # choose from all lowercase letter
    letters = string.ascii_letters + string.digits + string.punctuation
    result_str = ''.join(random.choice(letters) for i in range(length))
    logger.debug("Random string of length=%d is: %s" % (length, result_str))
    return result_str


# Workbench-specific helpers
def get_stack_service_id(*args):
    return "-".join(args)


def get_resource_name(*args):
    if KUBE_WORKBENCH_RESOURCE_PREFIX:
        return "%s-%s" % (KUBE_WORKBENCH_RESOURCE_PREFIX, "-".join(args))
    else:
        return "-".join(args)


def get_resource_namespace(username):
    if is_single_namespace():
        return KUBE_WORKBENCH_NAMESPACE
    else:
        return username


def is_single_namespace():
    return True if config.KUBE_WORKBENCH_NAMESPACE is not None and config.KUBE_WORKBENCH_NAMESPACE != '' else False


#
#
#
# Simplified API for Workbench endpoints to access
#
#
#
def initialize():
    if is_single_namespace():
        logger.debug("Starting in single-namespace mode: " + config.KUBE_WORKBENCH_NAMESPACE)
        try:
            create_namespace(config.KUBE_WORKBENCH_NAMESPACE)
        except Exception as err:
            logger.warning("Failed to create base namespace %s: %s" % (config.KUBE_WORKBENCH_NAMESPACE, err))

        if config.KUBE_WORKBENCH_RESOURCE_PREFIX:
            logger.debug("Using resource prefix: " + config.KUBE_WORKBENCH_RESOURCE_PREFIX)
    else:
        logger.debug("Starting in multi-namespace mode")


# Create necessary resources for a new user
def init_user(username):
    namespace = get_resource_namespace(username)
    # resource_name = get_resource_name(username)

    if not is_single_namespace():
        try:
            create_namespace(namespace_name=namespace)
        except ApiException as e:
            # Ignore conflict - creation of these resources is idempotent
            if e.status != 409:
                raise e

    try:
        create_persistent_volume_claim(namespace=namespace, pvc_name=username)
    except ApiException as e:
        # Ignore conflict - creation of these resources is idempotent
        if e.status != 409:
            raise e
    # create_resource_quota(namespace=namespace, quota_name=username, hard_quotas=DEFAULT_DEV_RESOURCE_QUOTA)
    # create_network_policy(namespace=username, policy_name=username)


# Creates the Kubernetes resources related to a userapp
def create_userapp(username, userapp, spec_map):
    namespace = get_resource_namespace(username)
    containers = []
    ingress_hosts = {}
    userapp_id = userapp['id']
    userapp_key = userapp['key']

    labels = {
        'manager': 'workbench',
        'user': username,
        'workbench-app': userapp_id
    }

    logger.info("Map of specs: %s" % spec_map)
    for stack_service in userapp['services']:
        service_key = stack_service['service']
        app_spec = spec_map.get(service_key, None)
        if app_spec is None:
            logger.error("Failed to find app_spec: %s" % service_key)
            raise AppSpecNotFoundError("Failed to find app_spec: %s" % service_key)
        stack_service_id = get_stack_service_id(userapp_id, service_key)
        resource_name = get_resource_name(userapp_id, userapp_key, service_key)
        service_ports = app_spec['ports'] if 'ports' in app_spec else []
        ingress_hosts[stack_service_id] = service_ports

        # Build up config from userapp env/config and appspec config
        configmap_data = userapp['config'] if 'config' in userapp else {}
        spec_config = app_spec['config'] if 'config' in app_spec else []
        for cfg in spec_config:
            if not cfg['canOverride']:
                # reset to spec value if we can't override
                configmap_data[cfg.name] = cfg['value'] if 'value' in cfg else ''
            if cfg['isPassword'] and cfg['canOverride'] and not cfg['value']:
                # generate password if none is provided
                configmap_data[cfg.name] = generate_random_password()

        # Create one pod container per-stack service
        containers.append({
            'name': stack_service_id,
            'resourceLimits': stack_service['resourceLimits'] if 'resourceLimits' in stack_service else app_spec[
                'resourceLimits'] if 'resourceLimits' in app_spec else {},
            'command': stack_service['command'] if 'command' in stack_service else None,
            'image': stack_service['image'] if 'image' in stack_service else app_spec['image'],
            'configmap': resource_name,  # not currently used
            'prestop': stack_service['prestop'] if 'prestop' in stack_service else None,
            'poststart': stack_service['poststart'] if 'poststart' in stack_service else None,
            'ports': service_ports,
        })

        # Create one Kubernetes service per-stack service
        create_service(service_name=resource_name,
                       namespace=namespace, labels=labels,
                       service_ports=service_ports)

        if len(configmap_data) > 0:
            # Create one Kubernetes configmap per-stack service
            create_configmap(namespace=namespace, configmap_name=resource_name, configmap_data=configmap_data)

    # Create one ingress per-stack
    create_ingress(ingress_name=get_resource_name(userapp_id, userapp_key),
                   namespace=namespace, labels=labels,
                   ingress_hosts=ingress_hosts)

    # Create one deployment per-stack (start with 0 replicas, aka "Stopped")
    create_deployment(deployment_name=get_resource_name(userapp_id, userapp_key),
                      namespace=namespace,
                      replicas=0,
                      labels=labels,
                      containers=containers)


# Cleans up the Kubernetes resources related to a userapp
def destroy_userapp(username, userapp):
    userapp_id = userapp['id']
    userapp_key = userapp['key']
    name = get_resource_name(userapp_id, userapp_key)
    namespace = get_resource_namespace(username)
    delete_deployment(name=name, namespace=namespace)
    delete_ingress(name=name, namespace=namespace)
    # TODO: networkpolicy? (currently unused)

    for stack_service in userapp['services']:
        service_key = stack_service['service']
        name = get_resource_name(userapp_id, userapp_key, service_key)
        delete_configmap(name=name, namespace=namespace)
        delete_service(name=name, namespace=namespace)

    return


#
#
# K8S entity helpers
#
#
def create_namespace(namespace_name, **kwargs):
    v1 = client.CoreV1Api()

    # TODO: Validation
    namespace_labels = kwargs['labels'] if 'labels' in kwargs else {}
    namespace_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    namespace = v1.create_namespace(body=client.V1Namespace(
        api_version='v1',
        kind='Namespace',
        metadata=client.V1ObjectMeta(
            name=namespace_name,
            annotations=namespace_annotations,
            labels=namespace_labels
        ),
    ))
    logger.debug("Created namespace resource: " + str(namespace))
    return namespace


def delete_namespace(name):
    v1 = client.CoreV1Api()
    v1.delete_namespace(name=name)
    logger.debug("Deleted namespace resource: %s" % name)
    return


def get_deployment(name, namespace):
    try:
        return client.AppsV1Api().read_namespaced_deployment(name=name, namespace=namespace)
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            return None
        else:
            logger.error("Error reading deployment resource: %s" % str(exc))
            raise exc


def patch_scale_deployment(deployment_name, namespace, replicas):
    deployment = get_deployment(name=deployment_name, namespace=namespace)
    if deployment is None:
        return None

    return client.AppsV1Api().patch_namespaced_deployment_scale(namespace=namespace, name=deployment_name,
                                                                body={'spec': {'replicas': replicas}})


def create_configmap(configmap_name, configmap_data, **kwargs):
    v1 = client.CoreV1Api()

    # TODO: Validation
    configmap_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    configmap_labels = kwargs['labels'] if 'labels' in kwargs else {}
    configmap_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    try:
        configmap = v1.create_namespaced_config_map(namespace=configmap_namespace, body=client.V1ConfigMap(
            api_version='v1',
            kind='ConfigMap',
            metadata=client.V1ObjectMeta(
                name=configmap_name,
                namespace=configmap_namespace,
                annotations=configmap_annotations,
                labels=configmap_labels
            ),
            data=configmap_data
        ))
        logger.debug("Created configmap resource: " + str(configmap))
        return configmap

    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            return None
        else:
            logger.error("Error creating configmap resource: %s" % str(exc))
            raise exc


def update_configmap(configmap_name, configmap_data, **kwargs):
    v1 = client.CoreV1Api()
    configmap_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    configmap_labels = kwargs['labels'] if 'labels' in kwargs else {}
    configmap_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    return v1.replace_namespaced_config_map(name=configmap_name,
                                            namespace=configmap_namespace,
                                            body=client.V1ConfigMap(
                                                api_version='v1',
                                                kind='ConfigMap',
                                                metadata=client.V1ObjectMeta(
                                                    name=configmap_name,
                                                    namespace=configmap_namespace,
                                                    annotations=configmap_annotations,
                                                    labels=configmap_labels
                                                ),
                                                data=configmap_data
                                            ))


def retrieve_configmap(configmap_name, **kwargs):
    v1 = client.CoreV1Api()
    configmap_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    configmap = v1.read_namespaced_config_map(configmap_name, configmap_namespace)

    return configmap.data


def delete_configmap(name, namespace):
    v1 = client.CoreV1Api()
    try:
        v1.delete_namespaced_config_map(name=name, namespace=namespace)
        logger.debug("Deleted configmap resource: %s/%s" % (namespace, name))
    except (ApiException, HTTPError) as exc:
        if not isinstance(exc, ApiException) or exc.status != 404:
            logger.error("Error deleting configmap resource: %s" % str(exc))
            raise exc


def create_persistent_volume_claim(pvc_name, **kwargs):
    v1 = client.CoreV1Api()

    # TODO: Validation
    pvc_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    pvc_labels = kwargs['labels'] if 'labels' in kwargs else {}
    pvc_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    pvc_storage_class = kwargs['storage_class'] if 'storage_class' in kwargs else ''
    pvc_volume_mode = kwargs['volume_mode'] if 'volume_mode' in kwargs else 'Filesystem'
    pvc_access_modes = kwargs['access_modes'] if 'access_modes' in kwargs else ['ReadWriteMany']
    pvc_request_storage = kwargs['request_storage'] if 'request_storage' in kwargs else '10Mi'
    pvc_volume_name = kwargs['volume_name'] if 'volume_name' in kwargs else None

    if pvc_volume_name:
        logger.warning("Warning: PVC Volume Name is set - manual claim binding may be necessary.")

    pvc_spec = client.V1PersistentVolumeClaimSpec(
        volume_name=pvc_volume_name,
        access_modes=pvc_access_modes,
        volume_mode=pvc_volume_mode,
        resources=client.V1ResourceRequirements(
            requests={
                'storage': pvc_request_storage
            }
        )
    )

    if pvc_storage_class != '':
        pvc_spec.storage_class_name = pvc_storage_class

    pvc = v1.create_namespaced_persistent_volume_claim(namespace=pvc_namespace, body=client.V1PersistentVolumeClaim(
        api_version='v1',
        kind='PersistentVolumeClaim',
        metadata=client.V1ObjectMeta(
            name=pvc_name,
            namespace=pvc_namespace,
            annotations=pvc_annotations,
            labels=pvc_labels
        ),
        spec=pvc_spec
    ))
    logger.debug("Created pvc resource: " + str(pvc))
    return pvc


def get_image_string(container_image):
    # Required values
    name = container_image.get('name', '')

    # Optional values
    repo = container_image.get('repo', None)
    tags = container_image.get('tags', [])
    tag = tags[0] if len(tags) > 0 else 'latest'
    return '%s/%s:%s' % (repo, name, tag) if repo is not None else '%s:%s' % (name, tag)


# Containers:
#   "busybox" -> { name, configmap, image, lifecycle, ports, command }
def create_deployment(deployment_name, containers, labels, **kwargs):
    appv1 = client.AppsV1Api()

    # TODO: Validation
    deployment_labels = labels
    deployment_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    deployment_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    deployment_replicas = kwargs['replicas'] if 'replicas' in kwargs else 0

    podspec_annotations = kwargs['pod_annotations'] if 'pod_annotations' in kwargs else {}

    service_account_name = kwargs['service_account'] if 'service_account' in kwargs else None

    # Build a podspec from given containers and other parameters
    podspec = client.V1PodSpec(
        service_account_name=service_account_name,
        containers=[
            client.V1Container(
                name=container['name'],
                command=container['command'],
                # TODO: resource limits
                # resources=V1ResourceRequirements(),
                #
                # TODO: create configmap with env
                # env_from=[
                #     client.V1EnvFromSource(
                #         config_map_ref=client.V1ConfigMapEnvSource(
                #             name=container['configmap']
                #         )
                #     )
                # ],
                #
                # TODO: container.lifecycle?
                lifecycle=container['lifecycle'] if 'lifecycle' in container else None,
                image=get_image_string(container['image']),
                ports=[
                    client.V1ContainerPort(
                        name='%s%s' % (port['protocol'] if 'protocol' in port else 'tcp', str(port['port'])),
                        container_port=port['port'],
                        protocol='TCP'
                        # port['protocol'].upper() if 'protocol' in port and port['protocol'] != 'http' else
                    ) for port in container['ports']
                ]
            ) for container in containers
        ])

    try:
        body = client.V1Deployment(
            api_version='apps/v1',
            kind='Deployment',
            metadata=client.V1ObjectMeta(
                name=deployment_name,
                namespace=deployment_namespace,
                labels=deployment_labels,
                annotations=deployment_annotations
            ),
            spec=client.V1DeploymentSpec(
                replicas=deployment_replicas,
                selector={"matchLabels": deployment_labels},
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        name=deployment_name,
                        namespace=deployment_namespace,
                        annotations=podspec_annotations,
                        labels=deployment_labels
                    ),
                    spec=podspec
                )
            )
        )

        logger.info("Creating deployment resource: %s" % str(body))
        deployment = appv1.create_namespaced_deployment(namespace=deployment_namespace, body=body)
        logger.debug("Created deployment resource: %s" % str(deployment))
        return deployment
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            return None
        else:
            logger.error("Error creating service resource: %s" % str(exc))
            raise exc


def delete_deployment(name, namespace):
    appv1 = client.AppsV1Api()
    try:
        appv1.delete_namespaced_deployment(name=name, namespace=namespace)
        logger.debug("Deleted deployment resource: %s/%s" % (namespace, name))
    except (ApiException, HTTPError) as exc:
        if not isinstance(exc, ApiException) or exc.status != 404:
            logger.error("Error deleting deployment resource: %s" % str(exc))
            raise exc


# Expected format:
#    service_ports = {
#        'http': 80,
#        'https': 443
#    }
def create_service(service_name, service_ports, labels, **kwargs):
    v1 = client.CoreV1Api()

    # TODO: Validation
    service_labels = labels
    service_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    service_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    try:
        service = v1.create_namespaced_service(namespace=service_namespace, body=client.V1Service(
            api_version='v1',
            kind='Service',
            metadata=client.V1ObjectMeta(
                name=service_name,
                namespace=service_namespace,
                annotations=service_annotations,
                labels=service_labels
            ),
            spec=client.V1ServiceSpec(
                selector=service_labels,
                ports=[
                    client.V1ServicePort(
                        name=port['name'] if 'name' in port else None,
                        port=int(port['port']),
                        protocol='TCP'
                        # port['protocol'].upper() if 'protocol' in port and port['protocol'] != 'http' else
                    ) for port in service_ports
                ]
            )
        ))
        logger.debug("Created service resource: " + str(service))
        return service

    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            return None
        else:
            logger.error("Error creating service resource: %s" % str(exc))
            raise exc


def delete_service(name, namespace):
    v1 = client.CoreV1Api()
    try:
        v1.delete_namespaced_service(name=name, namespace=namespace)

        logger.debug("Deleted service resource: %s/%s" % (namespace, name))
    except (ApiException, HTTPError) as exc:
        if not isinstance(exc, ApiException) or exc.status != 404:
            logger.error("Error deleting service resource: %s" % str(exc))
            raise exc


def create_ingress(ingress_name, ingress_hosts, labels, **kwargs):
    networkingv1 = client.NetworkingV1Api()
    print("Creating ingress resource:")

    # TODO: Validation
    ingress_labels = labels
    ingress_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    ingress_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    try:
        ingress = networkingv1.create_namespaced_ingress_with_http_info(ingress_namespace, client.V1Ingress(
            api_version='networking.k8s.io/v1',
            kind='Ingress',
            metadata=client.V1ObjectMeta(
                name=ingress_name,
                namespace=ingress_namespace,
                annotations=ingress_annotations,
                labels=ingress_labels,
            ),
            spec=client.V1IngressSpec(rules=[
                client.V1IngressRule(
                    host='%s.%s' % (stack_service_id, config.DOMAIN),
                    http=client.V1HTTPIngressRuleValue(
                        paths=[client.V1HTTPIngressPath(
                            path_type='ImplementationSpecific',
                            path='/',  # Since we use host-based routing
                            backend=client.V1IngressBackend(
                                service=client.V1IngressServiceBackend(
                                    name=port['name'] if 'name' in port else stack_service_id,
                                    port=client.V1ServiceBackendPort(
                                        number=port['port']
                                    )
                                )
                            )
                        ) for port in ingress_hosts[stack_service_id]]
                    )
                ) for stack_service_id in ingress_hosts.keys()
            ])
        ))
        logger.debug("Created ingress resource: " + str(ingress))
        # for i in ret.items:
        #    logger.debug("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
        return ingress

    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            return None
        else:
            logger.error("Error creating ingress resource: %s" % str(exc))
            raise exc


def delete_ingress(name, namespace):
    networkingv1 = client.NetworkingV1Api()
    try:
        networkingv1.delete_namespaced_ingress(name=name, namespace=namespace)

        logger.debug("Deleted ingress resource: %s/%s" % (namespace, name))

    except (ApiException, HTTPError) as exc:
        if not isinstance(exc, ApiException) or exc.status != 404:
            logger.error("Error deleting ingress resource: %s" % str(exc))
            raise exc


def get_pods():
    v1 = client.CoreV1Api()
    print("Listing pods with their IPs:")
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
        print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
    # return { 'name': ingress_name, 'namespace': ingress_namespace }, 201


#
#
#
# Kubernetes Security
#
#
#
def create_network_policy(policy_name, **kwargs):
    networkingv1 = client.NetworkingV1Api()

    policy_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    policy_labels = kwargs['labels'] if 'labels' in kwargs else {}
    policy_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    match_labels = kwargs['match_labels'] if 'match_labels' in kwargs else {}
    match_expressions = kwargs['match_expressions'] if 'match_expressions' in kwargs else []

    egress = kwargs['egress'] if 'egress' in kwargs else []
    ingress = kwargs['ingress'] if 'ingress' in kwargs else []

    egress_len = len(egress)
    ingress_len = len(ingress)
    policy_types = \
        ["Ingress", "Egress"] if ingress_len > 0 and egress_len > 0 else \
            ["Ingress"] if ingress_len > 0 and egress_len == 0 else \
                ["Egress"] if egress_len > 0 and ingress_len == 0 else \
                    []

    if not policy_types:
        logger.warning("Warning: Creating NetworkPolicy with empty policy_types")

    if not match_labels and not match_expressions:
        logger.warning("Warning: Creating NetworkPolicy that would operate on all resources")

    policy = networkingv1.create_namespaced_network_policy(namespace=policy_namespace, body=client.V1NetworkPolicy(
        api_version='v1',
        kind='NetworkPolicy',
        metadata=client.V1ObjectMeta(
            name=policy_name,
            namespace=policy_namespace,
            annotations=policy_annotations,
            labels=policy_labels
        ),
        spec=client.V1NetworkPolicySpec(
            egress=egress,
            ingress=ingress,
            policy_types=policy_types,
            pod_selector=client.V1LabelSelector(
                match_expressions=match_expressions,
                match_labels=match_labels
            )
        )
    )
                                                           )
    return policy


def delete_network_policy(name, **kwargs):
    networkingv1 = client.NetworkingV1Api()
    namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'

    try:
        networkingv1.delete_namespaced_network_policy(namespace=namespace, name=name)
        logger.debug("Deleted networkpolicy resource: %s/%s" % (namespace, name))
    except (ApiException, HTTPError) as exc:
        if not isinstance(exc, ApiException) or exc.status != 404:
            logger.error("Error deleting networkpolicy resource: %s" % str(exc))
            raise exc


def create_resource_quota(quota_name, hard_quotas, **kwargs):
    v1 = client.CoreV1Api()

    quota_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    quota_labels = kwargs['labels'] if 'labels' in kwargs else {}
    quota_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    try:
        quota = v1.create_namespaced_resource_quota(quota_namespace, body=client.V1ResourceQuota(
            api_version='v1',
            kind='ResourceQuota',
            metadata=client.V1ObjectMeta(
                name=quota_name,
                namespace=quota_namespace,
                annotations=quota_annotations,
                labels=quota_labels
            ),
            spec=client.V1ResourceQuotaSpec(
                scope_selector=client.V1ScopeSelector(
                    match_expressions=[
                        # TODO: Selector for namespace and/or user labels
                        # client.V1ScopedResourceSelectorRequirement(
                        # scop
                        # )
                    ]
                ),
                hard=hard_quotas
            )
        ))
        return quota
    except (ApiException, HTTPError) as exc:
        if not isinstance(exc, ApiException) or exc.status != 409:
            logger.error("Error creating networkpolicy resource: %s" % str(exc))
            raise exc


#
#
#
# V2 / CRD Stuff below here
#
#
#
def list_custom_app_specs():
    custom = client.CustomObjectsApi()
    return custom.list_cluster_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, CRD_APPSPECS_PLURAL)


def create_custom_app_spec(app_spec):
    custom = client.CustomObjectsApi()
    return custom.create_cluster_custom_object(
        group=CRD_GROUP_NAME,
        plural=CRD_APPSPECS_PLURAL,
        version=CRD_VERSION_V1,
        body={
            "apiVersion": "%s/%s" % (CRD_GROUP_NAME, CRD_VERSION_V1),
            "kind": CRD_APPSPECS_KIND,
            "metadata": {"name": "mongo"},
            "spec": app_spec,
        }
    )


def retrieve_custom_app_spec(key):
    custom = client.CustomObjectsApi()
    return custom.get_cluster_custom_object(group=CRD_GROUP_NAME,
                                            version=CRD_VERSION_V1,
                                            plural=CRD_APPSPECS_PLURAL,
                                            name=key)['spec']


def replace_custom_app_spec(key, app_spec):
    custom = client.CustomObjectsApi()
    return custom.replace_cluster_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, CRD_APPSPECS_PLURAL,
                                                name=key, body=app_spec)


def delete_custom_app_spec(key):
    custom = client.CustomObjectsApi()
    return custom.delete_cluster_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, CRD_APPSPECS_PLURAL,
                                               name=key)


def list_custom_user_apps(namespace):
    custom = client.CustomObjectsApi()
    return custom.list_namespaced_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, namespace, CRD_USERAPPS_PLURAL)
    # return custom.list_namespaced_custom_object(group=CRD_GROUP_NAME, version=CRD_VERSION_V1,
    #                                            plural=CRD_USERAPPS_PLURAL, namespace=namespace)


def create_custom_user_app(stack, namespace):
    custom = client.CustomObjectsApi()
    return custom.create_namespaced_custom_object(
        group=CRD_GROUP_NAME,
        plural=CRD_USERAPPS_PLURAL,
        namespace=namespace,
        version=CRD_VERSION_V1,
        body={
            "apiVersion": "%s/%s" % (CRD_GROUP_NAME, CRD_VERSION_V1),
            "kind": CRD_USERAPPS_KIND,
            "metadata": {
                "name": stack['id'],
                "namespace": namespace
            },
            "spec": stack,
        }
    )


def retrieve_custom_user_app(name, namespace):
    custom = client.CustomObjectsApi()
    return custom.get_namespaced_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, CRD_USERAPPS_KIND,
                                               name=name, namespace=namespace)['spec']


def replace_custom_user_app(name, namespace, user_app):
    custom = client.CustomObjectsApi()
    return custom.replace_namespaced_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, CRD_USERAPPS_KIND,
                                                   name=name, namespace=namespace,
                                                   body=user_app)


def delete_custom_user_app(name, namespace):
    custom = client.CustomObjectsApi()
    return custom.delete_namespaced_custom_object(CRD_GROUP_NAME, CRD_VERSION_V1, CRD_USERAPPS_KIND,
                                                  name=name, namespace=namespace)
