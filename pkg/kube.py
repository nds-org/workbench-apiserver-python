import logging
import json
import time
from kubernetes import client, config as kubeconfig, watch
from kubernetes.client import ApiException
from requests import HTTPError

from pkg import config
from pkg.config import KUBE_WORKBENCH_NAMESPACE, KUBE_WORKBENCH_RESOURCE_PREFIX

CRD_GROUP_NAME = "ndslabs.org"
CRD_VERSION_V1 = "v1"
CRD_APPSPECS_PLURAL = "workbenchappspecs"
CRD_USERAPPS_PLURAL = "workbenchuserapps"
CRD_APPSPECS_KIND = "WorkbenchAppSpec"
CRD_USERAPPS_KIND = "WorkbenchUserApp"


logger = logging.getLogger('kube')

kubeconfig.load_kube_config()
custom = client.CustomObjectsApi()

# TODO: V2 - watch custom resources and react accordingly
#watched_namespaces = ["test"]
#for namespace in watched_namespaces:
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


# Create necessary resource for a new user
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
    for stack_service in userapp['services']:
        service_key = stack_service['service']
        app_spec = spec_map[service_key]
        if app_spec is None:
            logger.error("Failed to find app_spec: %s" % service_key)
            continue
        stack_service_id = get_stack_service_id(userapp_id, service_key)
        resource_name = get_resource_name(stack_service_id)
        service_ports = app_spec['ports'] if 'ports' in app_spec else None
        ingress_hosts[stack_service_id] = service_ports

        # Create one pod container per-stack service
        containers.append({
            'name': stack_service_id,
            'command': stack_service['command'] if 'command' in stack_service else None,
            'image': stack_service['image'] if 'image' in stack_service else app_spec['image'],
            'configmap': "%s-config" % resource_name,  # not currently used
            'prestop': stack_service['prestop'] if 'prestop' in stack_service else None,
            'poststart': stack_service['poststart'] if 'poststart' in stack_service else None,
            'ports': service_ports,
        })

        # Create one Kubernetes service container per-stack service
        create_service(service_name=resource_name,
                       namespace=namespace,
                       service_ports=service_ports)

    # Create one ingress per-stack
    create_ingress(ingress_name=get_resource_name(userapp_id),
                   namespace=namespace,
                   ingress_hosts=ingress_hosts)

    # Create one deployment per-stack (start with 0 replicas, aka Stopped)
    create_deployment(deployment_name=get_resource_name(userapp_id),
                      namespace=namespace,
                      replicas=0,
                      containers=containers)


# Cleans up the Kubernetes resources related to a userapp
def destroy_userapp(username, userapp):
    appId = userapp['id']
    namespace = get_resource_namespace(username)
    delete_deployment(appId, namespace=namespace)
    delete_ingress(appId, namespace=namespace)
    for stack_service in userapp['services']:
        delete_service(stack_service['id'], namespace=namespace)

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


def patch_scale_deployment(deployment_name, namespace, replicas):
    appsv1 = client.AppsV1Api()
    return appsv1.patch_namespaced_deployment_scale(namespace=namespace, name=deployment_name, body=client.V1Deployment(
        spec=client.V1DeploymentSpec(
            replicas=replicas
        )
    ))


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


def update_config_map(configmap_name, configmap_data, **kwargs):
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


def get_config_map(configmap_name, **kwargs):
    v1 = client.CoreV1Api()
    configmap_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    configmap = v1.read_namespaced_config_map(configmap_name, configmap_namespace)

    return configmap.data


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


# Containers:
#   "busybox" -> { name, configmap, image, lifecycle, ports, command }
def create_deployment(deployment_name, containers, **kwargs):
    appv1 = client.AppsV1Api()

    # TODO: Validation
    deployment_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    deployment_labels = kwargs['labels'] if 'labels' in kwargs else {}
    deployment_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    deployment_replicas = kwargs['replicas'] if 'replicas' in kwargs else 0

    podspec_annotations = kwargs['pod_annotations'] if 'pod_annotations' in kwargs else {}

    service_account_name = kwargs['service_account'] if 'service_account' in kwargs else 'workbench'

    # TODO: Abstract to parameter array
    #configmap_name = "%s-config" % deployment_name
    #container_name = 'workbench-container'
    #container_image = 'k8s.gcr.io/busybox'
    #container_command = ["/bin/sh", "-c", "env"]
    #container_poststart_command = ["/bin/sh", "-c", "echo Hello from the postStart handler > /usr/share/message/postStart"]
    #container_prestop_command = ["/bin/sh", "-c", "echo Hello from the preStop handler > /usr/share/message/preStop"]
    #container_ports = [80, 443]

    #client.V1Lifecycle(
    #    post_start=client.V1Handler(
    #        _exec=client.V1ExecAction(
    #            command=container_poststart_command
    #        )
    #    ),
    #    pre_stop=client.V1Handler(
    #        _exec=client.V1ExecAction(
    #            command=container_prestop_command
    #        )
    #    ),
    #)

    podspec = client.V1PodSpec(
        service_account_name=service_account_name,
        containers=[
            client.V1Container(
                name=container['name'],
                command=container['command'],
                env_from=[
                    client.V1EnvFromSource(
                        config_map_ref=client.V1ConfigMapEnvSource(
                            name=container['configmap']
                        )
                    )
                ],
                # TODO: container.lifecycle?
                lifecycle=container['lifecycle'] if 'lifecycle' in container else None,
                image=container['image'],
                ports=[
                    client.V1ContainerPort(
                        name=port,
                        container_port=container['ports'][port]
                    ) for port in container['ports']
                ]
            ) for container in containers
        ])

    try:
        deployment = appv1.create_namespaced_deployment(namespace=deployment_namespace, body=client.V1Deployment(
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
                selector=client.V1LabelSelector(
                    match_labels=deployment_labels
                ),
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
        ))
        logger.debug("Created deployment resource: " + str(deployment))
        return deployment
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            return None
        else:
            logger.error("Error creating service resource: %s" % str(exc))
            raise exc


def delete_deployment(name, namespace):
    appv1 = client.AppsV1Api()
    appv1.delete_namespaced_deployment(name=name, namespace=namespace)
    logger.debug("Deleted deployment resource: %s/%s" % (namespace, name))
    return


# Expected format:
#    service_ports = {
#        'http': 80,
#        'https': 443
#    }
def create_service(service_name, service_ports, **kwargs):
    v1 = client.CoreV1Api()

    # TODO: Validation
    service_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    service_labels = kwargs['labels'] if 'labels' in kwargs else {}
    service_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}
    print(service_ports)
    built_ports = []
    for port in service_ports:
        print(str(json.dumps(port)))
        built_ports.append(client.V1ServicePort(
                    port=port['port'],
                    protocol=port['protocol']
                ))
    print(built_ports)
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
                ports=built_ports
            )
        ))
        logger.debug("Created service resource: " + str(service))
        return service

    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 409:
            return None
        else:
            logger.error("Error creating service resource: %s" % str(e))
            raise exc


def delete_service(name, namespace):
    v1 = client.CoreV1Api()

    v1.delete_namespaced_service(name=name, namespace=namespace)

    logger.debug("Deleted service resource: %s/%s" % (namespace, name))

    return


def create_ingress(ingress_name, ingress_hosts, **kwargs):
    networkingv1 = client.NetworkingV1Api()
    print("Creating ingress resource:")

    # TODO: Validation
    ingress_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    ingress_labels = kwargs['labels'] if 'labels' in kwargs else {}
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
                        paths=[
                            client.V1HTTPIngressPath(
                                path_type='ImplementationSpecific',
                                path='/',  # Since we use host-based routing
                                backend=client.V1IngressBackend(
                                    service=client.V1IngressServiceBackend(
                                        name=stack_service_id,
                                        port=client.V1ServiceBackendPort(
                                            number=ingress_hosts[stack_service_id]
                                        )
                                    )
                                )
                            )
                        ]
                    )
                ) for stack_service_id in ingress_hosts.keys()
            ])
        ))
        logger.debug("Created ingress resource: " + str(ingress))
        #for i in ret.items:
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

    networkingv1.delete_namespaced_ingress(name=name, namespace=namespace)

    logger.debug("Deleted ingress resource: %s/%s" % (namespace, name))

    return


def get_pods():
    v1 = client.CoreV1Api()
    print("Listing pods with their IPs:")
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
        print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
    #return { 'name': ingress_name, 'namespace': ingress_namespace }, 201


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


def create_resource_quota(quota_name, hard_quotas, **kwargs):
    v1 = client.CoreV1Api()

    quota_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    quota_labels = kwargs['labels'] if 'labels' in kwargs else {}
    quota_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

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
                  #client.V1ScopedResourceSelectorRequirement(
                      # scop
                  #)
              ]
            ),
            hard=hard_quotas
        )
    ))
    return quota


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
    #return custom.list_namespaced_custom_object(group=CRD_GROUP_NAME, version=CRD_VERSION_V1,
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
