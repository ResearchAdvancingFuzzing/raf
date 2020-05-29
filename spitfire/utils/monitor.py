

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

        # count number of inputs that cover each edge
        edge_count = {}
        inp_edges = {}
        for inp_id in C:
            inp = kbs.GetInputById(kbp.id(uuid=inp_id))
            try:
                print ("covg for inp %s" % (inp_id))
                inp_edges[inp_id] = set([])
                n = 0
                for e in kbs.GetEdgeCoverageForInput(inp):
                    et = tuple([(i.module.uuid,i.offset) for i in e.address])
                    if not (et in edge_count): edge_count[et] = 0
                    edge_count[et] += 1
                    inp_edges[inp_id].add(et)
                    n +=1
                print("%d edges" % n)
            except Exception as e:
                # XXX sometimes there's no covg?
                print (str(e))
                print ("Actually no covg?")
                pass

        print("Total of %d edges for all inputs" % len(edge_count))

        hist = {}
        counts_obs = set([])
        for et in edge_count.keys():
            c = edge_count[et] # this edge has c inputs
            counts_obs.add(c)
            if not c in hist:
                hist[c] = 0
            hist[c] += 1       # number of edges with c inputs
        list_counts_obs = list(counts_obs)
        list_counts_obs.sort()
        for c in list_counts_obs:
            print("%d edges with %d inputs" % (hist[c], c))
        
        # for each input in RC, (no covg measure), count number of
        # rare edges (only a small number of inputs cover that edge)
#        num_rare_edges = {}
#        for inp_id in inp_edges.keys():
#            num_rare_edges[inp_id] = 0
#            for et in inp_edges[inp_id]:
#                if edge_count[et] < RARE_EDGE_COUNT:
#                    num_rare_edges[inp_id] += 1
#
#
#        for inp_uuid in C:
#            c = kbs.GetEdgeCoverageForInput(inp
if __name__ == "__main__":
    logging.basicConfig()
    run()
