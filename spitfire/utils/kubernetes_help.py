# To use any of the functions in this file,
# access to the cluster must be set up first 

from kubernetes import client, utils, config
import os
from os.path import basename

namespace = os.environ.get("NAMESPACE")
counts_dir = "/%s/counts" % namespace
qcow_dir = "/qcows"

# Determines number of active fuzzing managers
def num_active_fm(namespace): 
    core_v1 = client.CoreV1Api()
    resp = core_v1.list_namespaced_pod(namespace=namespace)
    num_fm, num_pending = 0, 0
    for i in resp.items:
        pt = i.spec.containers[0].image
        s = i.status.phase
        # number of running or pending fuzzing managers
        if (s=="Running" or s=="Pending") and "fm:" in pt:
            num_fm += 1
        #if s=="Pending":
        #    num_pending += 1
    #print ("num_fm = %d" % num_fm)
    return num_fm

# Cleanup all "backend" jobs that have succeeded 
def cleanup_finished_jobs(namespace): 
    # Cleanup anything from before 
    batch_v1 = client.BatchV1Api()
    for cj in batch_v1.list_namespaced_job(namespace=namespace, label_selector='tier=backend').items: 
        if not cj.status.active and cj.status.succeeded: 
            batch_v1.delete_namespaced_job(name=cj.metadata.name, namespace=namespace, propagation_policy="Background") 

def container(namespace, name, image, command, args, port, volume_mounts): 

    return client.V1Container(
            name=name, command=command, args=args, image=image, 
            volume_mounts=volume_mounts,
            env_from=[client.V1EnvFromSource(
                client.V1ConfigMapEnvSource(name="dir-config"))],
            ports=None if not port else [client.V1ContainerPort(container_port=port)])


def create_job(cfg, api_instance, image, job_name, num, arg, namespace): 
    
    name ="%s-%s" % (job_name, str(num)) # unique name 
    command = ["python3.6"] 
    args = ["run.py"]
    args.extend(arg)

    metadata_job=client.V1ObjectMeta(name=name, labels={"tier": "backend"})
    metadata_pod=client.V1ObjectMeta(name=name)
    volume_mounts=[client.V1VolumeMount(name="%s-storage" % namespace, mount_path="/%s" % namespace)]
    volumes=[client.V1Volume(name="%s-storage" % namespace, 
        persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=namespace))]

    init_containers=None
    if job_name == "taint" or job_name == "coverage":
        qcow=cfg.taint.qcow
        init_volume_mounts=[client.V1VolumeMount(name=qcow_name, mount_path=qcow_dir)]
        init_containers=[container(namespace, "%s-install" % qcow_name, "busybox", \
            ["wget"], ["-O", "%s/%s" % (qcow_dir, basename(qcow)), qcow], None, init_volume_mounts)]
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
    #print(job_body)
    result = api_instance.create_namespaced_job(namespace=namespace, body=job_body)
    #print(result)

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


# count how many pods are in the various phases
# returns number that are running + pending
def take_stock(core_v1):
    resp = core_v1.list_pod_for_all_namespaces()
    resp = core_v1.list_namespaced_pod(namespace=namespace)
    count = {}
    for i in resp.items:
        pt = i.spec.containers[0].image
        if not (("k8s" in pt) or ("gcr.io" in pt) or ("knowledge" in pt) or ("init" in pt)):
            s = i.status.phase
            if not (s in count):
                count[s] = {}
            if not (pt in count[s]):
                count[s][pt] = 0
            count[s][pt] += 1
    rp = 0
    for s in count.keys():
        #print ("Status=%s:" % s)
        if s=="Running" or s=="Pending":
            rp += 1
        #for pt in count[s].keys():
            #print("  %d %s" % (count[s][pt], pt))
        #print("\n")
    return rp


