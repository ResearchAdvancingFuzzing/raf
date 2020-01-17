import drcov
import logging
import grpc
import hydra
import os
import os.path

import spitfire.protos.knowledge_base_pb2 as pb
import spitfire.protos.knowledge_base_pb2_grpc as rpc

@hydra.main(config_path="../../config/expt1/config.yaml")
def run(cfg):
    
    with grpc.insecure_channel('%s:%d' % (cfg.kb_host, cfg.kb_port)) as channel:
        stub = rpc.KnowledgeBaseStub(channel)

        for cov_file in os.listdir(cfg.coverage.coverage_directory):
            cov_path = os.path.join(cfg.coverage.coverage_directory, cov_file)
            cov = drcov.DrcovData(cov_path)

            modules = []
            for m in cov.modules:
                modules[m.id] = pb.Module(name=m.filename, base=m.base, end=m.end, filepath=m.path)

            i = 0
            for r in stub.AddModules(iter(modules)):
                modules[i] = r
                i += 1

            basic_blocks = []
                
            for bb in cov.basic_blocks:
                basic_blocks.append(pb.Address(module=modules[bb.mod_id], offset=bb.start))



if __name__ == '__main__':
    logging.basicConfig()
    run()
