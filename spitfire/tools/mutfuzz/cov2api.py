import drcov
import logging
import grpc
import hydra
import os
import os.path
import sys


p = os.path.abspath(__file__)
for i in range(10):
    (hd, tl) = os.path.split(p)
    if tl == "spitfire":
        print("adding path " + p)
        print("adding path " + hd)
        sys.path.append(p)
        sys.path.append(hd)
        sys.path.append(p + "/protos")
        break
    p = hd

import spitfire.protos.knowledge_base_pb2 as pb
import spitfire.protos.knowledge_base_pb2_grpc as rpc

@hydra.main(config_path="../../config/expt1/config.yaml")
def run(cfg):
    
    with grpc.insecure_channel('%s:%d' % (cfg.kb_host, cfg.kb_port)) as channel:
        stub = rpc.KnowledgeBaseStub(channel)
        for cov_file in os.listdir(cfg.coverage.coverage_directory):
            cov_path = os.path.join(cfg.coverage.coverage_directory, cov_file)

            print("parsing coverage file: " + cov_path)            

            cov = drcov.DrcovData(cov_path)

            modules = []
            for m in cov.modules:
                modules.insert(m.id, pb.Module(name=m.filename.strip(), base=m.base, end=m.end, filepath=m.path.strip()))

            i = 0
            for r in stub.AddModules(iter(modules)):
                modules[i] = r
                i += 1
                
            basic_blocks = []
            
            for bb in cov.basic_blocks:
                basic_blocks.append(pb.Address(module=modules[bb.mod_id], offset=bb.start))
                
            i = 0
            for r in stub.AddAddresses(iter(basic_blocks)):
                basic_blocks[i] = r
                i += 1

            

if __name__ == '__main__':
    logging.basicConfig()
    run()
