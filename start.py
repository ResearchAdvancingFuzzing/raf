

# Expect this to run from HOST
# i.e. not from a kubernetes thingy
import numpy as np
import os
import sys
import grpc
import hydra
import logging
import time
from kubernetes import client, utils, config

spitfire_dir = os.environ.get("SPITFIRE_DIR")
spitfire_dir = "/home/hpreslier/raf/spitfire"
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(os.path.realpath(os.path.join(spitfire_dir, "..")))
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

# we need take in as a paramater the unique ID 
# then we need to set up a persistent volume claim for our persistent volume
# were all of the data will be held...

# <name> container in <namespace> with volume mounts and env configured
# command and args are a list or None
# port is a port # or None
def container(namespace, name, image, command, args, port): 
        return client.V1Container(
            name=name, command=command, args=args, image=image, 
            volume_mounts=[client.V1VolumeMount(
                name="%s-storage" % namespace, mount_path="/%s" % namespace)],
            env_from=[client.V1EnvFromSource(
                client.V1ConfigMapEnvSource(name="dir-config"))],
            ports=None if not port else [client.V1ContainerPort(container_port=port)])

@hydra.main(config_path=f"{spitfire_dir}/config/config.yaml") 
def run(cfg): 
    namespace = cfg.campaign.id
    storage = cfg.campaign.storage
   
    # Make sure campaign id is alphanumerical
    if not namespace.isalnum(): 
        return "Campaign ID must consist of letters and numbers only." 

    # Setup access to cluster 
    config.load_kube_config()
    core_api_instance = client.CoreV1Api()
    batch_api_instance = client.BatchV1Api() 
    apps_api_instance = client.AppsV1Api()
    rbac_api_instance = client.RbacAuthorizationV1Api() 
    

    # Create the namespace for the campaign
    res = core_api_instance.create_namespace(client.V1Namespace(
        metadata=client.V1ObjectMeta(name=namespace)))
     
    # Create the permissions 
    
    role_exists = False
    name="raf-roles"
    for role in rbac_api_instance.list_cluster_role().items: 
        if role.metadata.name == name:
            role_exists = True

    if not role_exists: 
        rbac_api_instance.create_cluster_role(client.V1Role(
            metadata=client.V1ObjectMeta(name=name), 
            rules=[client.V1PolicyRule(
                api_groups=["", "apps", "batch"],
                resources=["configmaps", "persistentvolumeclaims", "pods", "services", "deployments", "jobs", "cronjobs"],
                verbs=["list", "get", "create", "update", "delete", "watch"])]))

        rbac_api_instance.create_cluster_role_binding(client.V1RoleBinding(
            metadata=client.V1ObjectMeta(name="%s-binding" % name), 
            subjects=[client.V1Subject(
                kind="Group",
                name="system:serviceaccounts", 
                api_group="rbac.authorization.k8s.io")],
            role_ref=client.V1RoleRef(
                kind="ClusterRole",
                name=name,
                api_group="rbac.authorization.k8s.io")))
    '''
    name="role-%s" % namespace
    rbac_api_instance.create_namespaced_role(namespace, client.V1Role(
        metadata=client.V1ObjectMeta(name=name), 
        rules=[client.V1PolicyRule(
            api_groups=["", "apps", "batch"],
            resources=["configmaps", "persistentvolumeclaims", "pods", "services", "deployments", "jobs", "cronjobs"],
            verbs=["list", "get", "create", "update", "delete", "watch"])]))

    rbac_api_instance.create_namespaced_role_binding(namespace, client.V1RoleBinding(
        metadata=client.V1ObjectMeta(name="%s-binding" % name), 
        subjects=[client.V1Subject(
            kind="Group",
            name="system:serviceaccounts", 
            api_group="rbac.authorization.k8s.io")],
        role_ref=client.V1RoleRef(
            kind="Role",
            name=name,
            api_group="rbac.authorization.k8s.io")))
    '''

    # Create the config map
    core_api_instance.create_namespaced_config_map(namespace, 
            client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name="dir-config"), 
                data={"TARGET_DIR": "/target", "TARGET_INSTR_DIR": "/target-instr", 
                    "CORPUS_DIR": "/seeds", "SPITFIRE_DIR": "/spitfire",\
                    "INPUTS_DIR": "/inputs", "REPLAY_DIR": "/replays",\
                    "NAMESPACE": namespace}))


    # Create the persistent volume 
    core_api_instance.create_persistent_volume(client.V1PersistentVolume(
        metadata=client.V1ObjectMeta(name="%s-pv" % namespace),
        spec=client.V1PersistentVolumeSpec(
            capacity={"storage": storage}, 
            access_modes=["ReadWriteMany"],
            host_path=client.V1HostPathVolumeSource(path="/tmp/%s" % namespace))))
    
    # Create the persistent volume claim for the campaign
    core_api_instance.create_namespaced_persistent_volume_claim(
            namespace, client.V1PersistentVolumeClaim(
                metadata=client.V1ObjectMeta(name=namespace), 
                spec=client.V1PersistentVolumeClaimSpec(
                    access_modes=["ReadWriteMany"],
                    resources=client.V1ResourceRequirements(requests={"storage": storage}))))
    
    # Create the init job-- sets up target, seeds, and code base in the PVC; 
    # sets up KB server and sends initial data to KB, starts FM 
    name="init"
    batch_api_instance.create_namespaced_job(
            namespace, client.V1Job(
                metadata=client.V1ObjectMeta(name=name), 
                spec=client.V1JobSpec(
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(name=name), 
                        spec=client.V1PodSpec(
                            containers=[container(namespace, name, "init:%s" % namespace, ["python3.6"], ["init.py"], None)],
                            init_containers=[
                                container(namespace, "target", "target:%s" % namespace,  None, None, None), 
                                container(namespace, "seed-corpus", "seed-corpus:%s" % namespace, None, None, None),
                                container(namespace, "spitfire", "spitfire:%s" % namespace, None, None, None)],
                            volumes=[client.V1Volume(
                                name="%s-storage" % namespace, 
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=namespace))],
                            restart_policy="Never")))))
   
    print("Campaign startup completed.") 

if __name__ == "__main__": 
    logging.basicConfig()
    run() 



