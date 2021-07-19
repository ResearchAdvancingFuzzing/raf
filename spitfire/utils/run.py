


# Expect this to run from HOST
# i.e. not from a kubernetes thingy

import os
import sys
import grpc
import hydra
import logging

#from pprint import pprint
#from kubernetes import client, utils, config

spitfire_dir = os.environ.get("SPITFIRE")
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(os.path.realpath(os.path.join(spitfire_dir, "..")))
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg


@hydra.main(config_path=f"{spitfire_dir}/config", config_name="config.yaml")
def run(cfg):

    # Connect to the knowledge base 
    with grpc.insecure_channel("172.17.0.5:61111") as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)
    
        # set fuzzing manager to run
        kbs.Run(kbp.Empty())

            
if __name__ == "__main__":
    logging.basicConfig()
    run()
