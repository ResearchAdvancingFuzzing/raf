from kubernetes import client, utils, config
import os
import yaml
import time
import grpc 
import sys
import hydra
import time 

# Setup env variables
namespace = os.environ.get("NAMESPACE") 
corpus_dir = "/%s%s" % (namespace, os.environ.get("CORPUS_DIR")) 
spitfire_dir = "/%s%s" % (namespace, os.environ.get("SPITFIRE_DIR")) 

# Add to path 
sys.path.append(spitfire_dir + "/protos")
sys.path.append(spitfire_dir + "/utils")

# Import 
import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg 
import coverage 

# This requires the config_server.yaml file named accordingly and the yaml deployment 
# specified first and the yaml service second 

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
def setup(cfg):

    # Setup access to cluster 
    config.load_incluster_config() 
    k_client = client.ApiClient() 
    core_api_instance = client.CoreV1Api()
    apps_api_instance = client.AppsV1Api()
    batch_beta_api_instance = client.BatchV1beta1Api() 

    # Create the kb server: deployment and service 
    deployment_name=cfg.knowledge_base.name
    labels={"server": deployment_name}
    res = apps_api_instance.create_namespaced_deployment(
           namespace, client.V1Deployment(
               metadata=client.V1ObjectMeta(name=deployment_name, labels=labels), 
                spec=client.V1DeploymentSpec(
                    selector=client.V1LabelSelector(match_labels=labels),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(name=deployment_name, labels=labels),
                        spec=client.V1PodSpec(
                            containers=[container(namespace, deployment_name, "knowledge-base:%s" % namespace, 
                                None, None, cfg.knowledge_base.port)],
                            volumes=[client.V1Volume(
                                name="%s-storage" % namespace, 
                                persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=namespace))])))))

    service_name="%s" % deployment_name
    core_api_instance.create_namespaced_service(
            namespace, client.V1Service(
                metadata=client.V1ObjectMeta(name=service_name), 
                spec=client.V1ServiceSpec(
                    selector=labels, 
                    ports=[client.V1ServicePort(
                        port=int(cfg.knowledge_base.port), 
                        target_port=int(cfg.knowledge_base.port))],
                    type="NodePort")))
  
    # Let's give this time to setup
    time.sleep(10)

    service = core_api_instance.list_namespaced_service(namespace=namespace)
    ip = service.items[0].spec.cluster_ip
    port = service.items[0].spec.ports[0].port
    node_port = service.items[0].spec.ports[0].node_port

    with grpc.insecure_channel('%s:%d' % (ip, port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)
        print("connected")
        
        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        target_kb = kbs.AddTarget(target_msg) 

        fuzz_inputs = []
        uuid = []
        for dirpath,_,filenames in os.walk(corpus_dir): 
            for f in filenames:
                input_msg = kbp.Input(filepath=os.path.join(dirpath, f), seed=True)
                fuzz_input = kbs.AddInput(input_msg)
                fuzz_inputs.append(fuzz_input)
                uuid.append(fuzz_input.uuid)
        uuid = b"".join(uuid)

        corpus_msg = kbp.Corpus(uuid=uuid, input=fuzz_inputs)
        corpus = kbs.AddCorpus(corpus_msg)
        
        # Experiment also needs a seed and a hash of the fuzzing manager 
        experiment_msg = kbp.Experiment(target=target_kb, seed_corpus=corpus)
        experiment = kbs.AddExperiment(experiment_msg)

        # set fuzzing manager to run
        kbs.Run(kbp.Empty())
        

    # Need to start up the fm and create the config map in this namespace  
    #core_api_instance.create_namespaced_config_map(namespace,
    #        client.V1ConfigMap(
    #            metadata=client.V1ObjectMeta(name="job-counts"), 
    #            data={"COUNTS_DIR": "/counts", "FUZZER": '0', "TAINT": '0', "COVERAGE": '0'}))

    name = "fm"
    batch_beta_api_instance.create_namespaced_cron_job(namespace, 
            client.V1beta1CronJob(
                metadata=client.V1ObjectMeta(name=name),
                spec=client.V1beta1CronJobSpec(schedule="*/1 * * * *", successful_jobs_history_limit=100, 
                    failed_jobs_history_limit=30, 
                    job_template=client.V1beta1JobTemplateSpec(metadata=client.V1ObjectMeta(name=name), 
                        spec=client.V1JobSpec(template=client.V1PodTemplateSpec(
                            spec=client.V1PodSpec(
                                containers=[container(namespace, name, "fm:%s" % namespace, None, None, None)],
                                volumes=[client.V1Volume(
                                    name="%s-storage" % namespace, 
                                    persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                        claim_name=namespace))],
                                restart_policy="OnFailure")))))))
    
    

if __name__ == '__main__':
    setup()
