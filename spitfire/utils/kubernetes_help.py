# To use any of the functions in this file,
# access to the cluster must be set up first 

from kubernetes import client, utils, config
import os
from os.path import basename

namespace = os.environ.get("NAMESPACE")
counts_dir = "/%s/counts" % namespace
qcow_dir = "/qcows"

# Before almost all of these functions can be used, you need to have 
# loaded cluster configuration information
# Either out of cluster with config.load_kube_config
# Or in cluster with config.load_incluster_config

# Determines number of active fuzzing managers in the namespace 
def active_fm(namespace): 
    core_v1 = client.CoreV1Api()
    resp = core_v1.list_namespaced_pod(namespace=namespace)
    num_fm, num_pending = 0, 0
    for i in resp.items:
        pt = i.spec.containers[0].image
        s = i.status.phase
        # number of running or pending fuzzing managers
        if (s=="Running" or s=="Pending") and "fm:" in pt:
            num_fm += 1
    return num_fm

# Cleanup all "backend" jobs that have succeeded 
def cleanup_finished_jobs(namespace): 
    # Cleanup anything from before 
    batch_v1 = client.BatchV1Api()
    for cj in batch_v1.list_namespaced_job(namespace=namespace, 
            label_selector='tier=backend').items: 
        if not cj.status.active and cj.status.succeeded: 
            batch_v1.delete_namespaced_job(name=cj.metadata.name, 
                    namespace=namespace, propagation_policy="Background") 

# Helper function for creating a job
def container(namespace, name, image, command, args, port, volume_mounts): 
    return client.V1Container(
            name=name, command=command, args=args, image=image, 
            volume_mounts=volume_mounts,
            env_from=[client.V1EnvFromSource(
                client.V1ConfigMapEnvSource(name="dir-config"))],
            ports=None if not port else [client.V1ContainerPort(container_port=port)])


def create_job(cfg, image, job_name, num, arg, namespace): 
    batch_v1 = client.BatchV1Api()

    name ="%s-%s" % (job_name, str(num)) # unique name 
    command = ["python3.6"] 
    args = ["run.py"]
    args.extend(arg)

    metadata_job=client.V1ObjectMeta(name=name, labels={"tier": "backend"})
    metadata_pod=client.V1ObjectMeta(name=name)
    volume_mounts=[client.V1VolumeMount(name="%s-storage" % namespace, 
        mount_path="/%s" % namespace)]
    volumes=[client.V1Volume(name="%s-storage" % namespace, 
        persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=namespace))]

    init_containers=None
    if job_name == "taint" or job_name == "coverage":
        qcow=cfg.taint.qcow
        init_volume_mounts=[client.V1VolumeMount(name=qcow_name, mount_path=qcow_dir)]
        init_containers=[container(namespace, "%s-install" % qcow_name, "busybox", 
            ["wget"], ["-O", "%s/%s" % (qcow_dir, basename(qcow)), qcow], 
            None, init_volume_mounts)]
        init_volume=[client.V1Volume(name=qcow_name, empty_dir=client.V1EmptyDirVolumeSource())]
        volume_mounts.extend(init_volume_mounts)
        volumes.extend(init_volume)

    containers=[container(namespace, name, image, command, args, None, volume_mounts)]
    restart_policy="OnFailure" 
    pod_spec=client.V1PodSpec(init_containers=init_containers, containers=containers, 
        volumes=volumes, restart_policy=restart_policy)
    pod_temp=client.V1PodTemplateSpec(metadata=metadata_pod, spec=pod_spec)
    job_spec=client.V1JobSpec(template=pod_temp)
    job_body=client.V1Job(metadata=metadata_job, spec=job_spec)
    result = batch_v1.create_namespaced_job(namespace=namespace, body=job_body)

class Job: 
    def __init__(self, name):
        self.name = name
        self.count_file = "%s/%s" % (counts_dir, name)
        # Setup the count; we need them to be persistent 
        try:
            with open(self.count_file) as f:
                self.count = int(f.read())
        except IOError:
            self.count = 0
        else:
            f.close() 

    def get_count(self): 
        return self.count

    def update_count_by(self, num): 
        with open(self.count_file, "w") as f:
            f.write(str(self.count + num))
        self.count += num
        return self.count 

def remove_units(val):
    for i,c in enumerate(val):
        if not c.isdigit():
            break
    units = val[i:]
    number = int(val[:i])
    return [number, units] 

# This has not been tested or used yet
# This only works for one node  
# We will also need permissions here to work 
def cluster_usages(to_print): 
    api = client.CustomObjectsApi()
    pod_resource = api.list_namespaced_custom_object("metrics.k8s.io", 
            "v1beta1", namespace, "pods")
    node_resource = api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
    [total_cpu, total_cpu_u] = remove_units(node_resource['items'][0]['usage']['cpu'])
    [total_mem, total_mem_u] = remove_units(node_resource['items'][0]['usage']['memory'])
    # Make everything m 
    cpu_usages, mem_usages = {}, {}
    for pod in pod_resource['items']: 
        [cpu_val, cpu_units] = remove_units(pod['containers'][0]['usage']['cpu'])
        [mem_val, mem_units] = remove_units(pod['containers'][0]['usage']['memory'])
        if cpu_units in cpu_usages:
            cpu_usages[cpu_units].append(cpu_val)
        else:
            cpu_usages[cpu_units] = [] 
        if mem_units in mem_usages: 
            mem_usages[mem_units].append(mem_val) 
        else:
            mem_usages[mem_units] = []

    if (len(mem_usages) == 1 and len(cpu_usages) == 1 and 
            total_cpu_u == list(cpu_usages.keys())[0] and
            total_mem_u == list(mem_usages.keys())[0]): # good to go
        total_mem_using = sum(mem_usages[list(mem_usages.keys())[0]]) 
        total_cpu_using = sum(cpu_usages[list(cpu_usages.keys())[0]])
        fraction_cpu = total_cpu_using / total_cpu
        fraction_mem = total_mem_using / total_mem
        if to_print:
            print(f"CPU percentage: {fraction_cpu} {total_cpu_u}") 
            print(f"MEM percentage: {fraction_mem} {total_mem_u}")
        return [fraction_cpu, fraction_mem]
    else:
        # conversions of units required, let's hope they just give us the same units 
        print("Results are diff units. NOT IMPLEMENTED")
        return []

# count how many pods are in the various phases
# returns number that are running + pending
def take_stock():
    core_v1 = client.CoreV1Api()
    resp = core_v1.list_namespaced_pod(namespace=namespace)
    count = {}
    for pod in resp.items:
        pod_name = pod.metadata.name
        pod_status = pod.status.phase
        if not pod_status in count:
            count[pod_status] = {}
        if not pod_name in count[pod_status]:
            count[pod_status][pod_name] = 0
        count[pod_status][pod_name] += 1
    rp = 0
    for status in count.keys():
        if status == "Running" or status == "Pending":
            rp += len(count[status])  
    return rp


