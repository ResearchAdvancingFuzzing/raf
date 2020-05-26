from kubernetes import client, utils, config
import os
import yaml
import time
import grpc 
import sys
import hydra
import time 
spitfire_dir = os.environ.get("SPITFIRE") 
sys.path.append("/")
print(spitfire_dir) 
sys.path.append(spitfire_dir)
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))
import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg 

corpus_dir = os.environ.get("CORPUS_DIR") 
# This requires the config_server.yaml file named accordingly and the yaml deployment 
# specified first and the yaml service second 
def create_kb_from_yaml(cfg, client, namespace):
    print("Starting server") 
    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    
    with open("/config_server.yaml") as f:
        kb = yaml.safe_load_all(f) 
        kb_deployment = next(kb) 
        kb_service = next(kb)
        assert (kb_deployment["spec"]["template"]["spec"]["containers"][0]["ports"][0]["name"] == \
                kb_service["spec"]["ports"][0]["targetPort"]) 
        kb_service["spec"]["clusterIP"] = cfg.knowledge_base.host
        kb_service["spec"]["ports"][0]["port"] = cfg.knowledge_base.port
        apps_v1.create_namespaced_deployment(body=kb_deployment, namespace=namespace)
        core_v1.create_namespaced_service(body=kb_service, namespace=namespace) 
    
    # Wait for the server to start running 
    time.sleep(10)

@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def setup(cfg):
    
    # Setup access to cluster 
    config.load_incluster_config() 
    k_client = client.ApiClient()
    
    # Create the kb server and check the status  
    create_kb_from_yaml(cfg, client, "default")

    # Send experiment information to the database 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
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
        
    print("here")  
    # Need to start up the fm
    utils.create_from_yaml(k_client, "/config_fm.yaml")


if __name__ == '__main__':
    setup()
