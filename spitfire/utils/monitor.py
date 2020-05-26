

# Expect this to run from HOST
# i.e. not from a kubernetes thingy

import os
import sys
import grpc
import hydra
import logging

from pprint import pprint
from kubernetes import client, utils, config

spitfire_dir = os.environ.get("SPITFIRE")
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(os.path.realpath(os.path.join(spitfire_dir, "..")))
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg


@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):

    # Setup access to cluster 
    config.load_kube_config()
    api_instance = client.CoreV1Api() # client.BatchV1Api()

    # peek at pods to see what's running / completed / etc
    resp = api_instance.list_pod_for_all_namespaces()
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
    for s in count.keys():
        print ("Status=%s:" % s)
        for pt in count[s].keys():
            print("  %d %s" % (count[s][pt], pt))
#        print("\n")
    
    
    
    # Connect to the knowledge base 
    with grpc.insecure_channel("172.17.0.5:61111") as channel:
#    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)


        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
        F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
        C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}
        ICV = {inp.uuid for inp in kbs.GetInputsWithoutCoverage(kbp.Empty())}
        T = {inp.uuid for inp in kbs.GetTaintInputs(kbp.Empty())}

        
        print("%d seeds" % len(S))
        print("%d fuzzed" % len(F))
        print("%d seedsfuzzed" % (len(S & F)))
        print("%d coverage" % (len(C)))
        print("%d seedscoverage" % (len(S & C)))
        print("%d taint" % len(T))
                
        
if __name__ == "__main__":
    logging.basicConfig()
    run()
