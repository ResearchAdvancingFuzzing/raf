

# Expect this to run from HOST
# i.e. not from a kubernetes thingy

import os
import sys
import hydra
import logging

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

    # Connect to the knowledge base 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)


        #S = set of original corpus seed inputs
        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
        print("%d Seeds" % (len(S)))
        for s in S: 
            print(s)
            
        #F = set of inputs we have done mutational fuzzing on so far
        F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
        print("%d Execution" % (len(F)))
        for f in F:
            print(f)
            
        #C = set of inputs for which we have measured coverage
        C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}
        print("%d Inputs With Coverage" % (len(C)))
        for c in C:
            print(c)
            
        #ICV = set of interesting inputs that got marginal covg (increased covg)
        ICV = {inp.uuid for inp in kbs.GetInputsWithoutCoverage(kbp.Empty())}
        print("%d Inputs without Coverage" % (len(ICV)))
        for icv in ICV:
            print(icv)
            
        #T = set of inputs for which we have done taint analysis
        T = {inp.uuid for inp in kbs.GetTaintInputs(kbp.Empty())}
        print("%d Taint Inputs" % (len(T)))
        for t in T:
            print(t) 

        
if __name__ == "__main__":
    logging.basicConfig()
    run()
