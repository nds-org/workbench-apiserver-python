import logging
import time
from kubernetes import client, config as kubeconfig, watch


CRD_GROUP_NAME = "ndslabs.org"
CRD_VERSION_V1 = "v1"
CRD_APPSPECS_PLURAL = "workbenchappspecs"
CRD_USERAPPS_PLURAL = "workbenchuserapps"
CRD_APPSPECS_KIND = "WorkbenchAppSpec"
CRD_USERAPPS_KIND = "WorkbenchUserApp"


logger = logging.getLogger('kube')

kubeconfig.load_kube_config()
custom = client.CustomObjectsApi()

watched_namespaces = ["test"]
for namespace in watched_namespaces:
    count = 10
    w = watch.Watch()
    for event in w.stream(custom.list_namespaced_custom_object,
                          group=CRD_GROUP_NAME,
                          version=CRD_VERSION_V1,
                          namespace=namespace,
                          plural=CRD_USERAPPS_PLURAL,
                          _request_timeout=60):
        print("Event: %s %s" % (event['type'], event['object']['metadata']['name']))
        count -= 1
        time.sleep(10)
        if not count:
            w.stop()


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


def patch_scale_deployment(name, namespace, replicas):
    appsv1 = client.AppsV1Api()
    return appsv1.patch_namespaced_deployment_scale(namespace=namespace, name=name, body=client.V1Deployment(
        spec=client.V1DeploymentSpec(
            replicas=replicas
        )
    ))


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


def create_configmap(configmap_name, configmap_data, **kwargs):
    v1 = client.CoreV1Api()

    # TODO: Validation
    configmap_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    configmap_labels = kwargs['labels'] if 'labels' in kwargs else {}
    configmap_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

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

    pvc = v1.create_namespaced_persistent_volume_claim(namespace=pvc_namespace, body=client.V1PersistentVolumeClaim(
        api_version='v1',
        kind='PersistentVolumeClaim',
        metadata=client.V1ObjectMeta(
            name=pvc_name,
            namespace=pvc_namespace,
            annotations=pvc_annotations,
            labels=pvc_labels
        ),
        spec=client.V1PersistentVolumeClaimSpec(
            storage_class_name=pvc_storage_class,
            volume_name=pvc_volume_name,
            access_modes=pvc_access_modes,
            volume_mode=pvc_volume_mode,
            resources=client.V1ResourceRequirements(
                requests={
                    'storage': pvc_request_storage
                }
            )
        )
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
    configmap_name = "%s-config" % deployment_name
    container_name = 'workbench-container'
    container_image = 'k8s.gcr.io/busybox'
    container_command = ["/bin/sh", "-c", "env"]
    container_poststart_command = ["/bin/sh", "-c", "echo Hello from the postStart handler > /usr/share/message/postStart"]
    container_prestop_command = ["/bin/sh", "-c", "echo Hello from the preStop handler > /usr/share/message/preStop"]
    container_ports = [80, 443]

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
                    name=key,
                    port=service_ports[key],
                ) for key in service_ports
            ]
        )
    ))
    logger.debug("Created service resource: " + str(service))
    return service


def create_ingress(ingress_name, service_name, service_port, **kwargs):
    networkingv1 = client.NetworkingV1Api()
    print("Creating ingress resource:")

    # TODO: Validation
    ingress_namespace = kwargs['namespace'] if 'namespace' in kwargs else 'default'
    ingress_labels = kwargs['labels'] if 'labels' in kwargs else {}
    ingress_annotations = kwargs['annotations'] if 'annotations' in kwargs else {}

    ingress_host = kwargs['host'] if 'host' in kwargs else 'example.local.ndslabs.org'
    ingress_path = kwargs['path'] if 'path' in kwargs else '/'
    ingress_pathtype = kwargs['path_type'] if 'path_type' in kwargs else 'ImplementationSpecific'

    service_name = kwargs['service_name'] if 'service_name' in kwargs else 'example'
    service_port = kwargs['service_ports'] if 'service_ports' in kwargs else 8080

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
                host=ingress_host,
                http=client.V1HTTPIngressRuleValue(
                    paths=[
                        client.V1HTTPIngressPath(
                            path_type=ingress_pathtype,
                            path=ingress_path,
                            backend=client.V1IngressBackend(
                                service=client.V1IngressServiceBackend(
                                    name=service_name,
                                    port=client.V1ServiceBackendPort(
                                        number=service_port
                                    )
                                )
                            )
                        )
                    ]
                )
            )
        ])
    ))
    logger.debug("Created ingress resource: " + str(ingress))
    #for i in ret.items:
    #    logger.debug("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
    return ingress


def get_pods():
    v1 = client.CoreV1Api()
    print("Listing pods with their IPs:")
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
        print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
    #return { 'name': ingress_name, 'namespace': ingress_namespace }, 201
