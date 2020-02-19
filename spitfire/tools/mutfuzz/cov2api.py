import drcov
import logging
import grpc
import hydra
import os
import os.path
import sys
from collections import Counter

p = os.path.abspath(__file__)
for i in range(10):
    (hd, tl) = os.path.split(p)
    if tl == "spitfire":
        sys.path.append(p)
        sys.path.append(hd)
        sys.path.append(p + "/protos")
        break
    p = hd

import spitfire.protos.knowledge_base_pb2 as pb
import spitfire.protos.knowledge_base_pb2_grpc as rpc
import google.protobuf.json_format

@hydra.main(config_path="../../config/expt1/config.yaml")
def run(cfg):    
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        stub = rpc.KnowledgeBaseStub(channel)
        os.chdir("/python") # for now
        for cov_file in os.scandir(cfg.coverage.coverage_directory):
            if not cov_file.is_file() or not cov_file.name.endswith('.coverage'):
                continue
            
            cov = drcov.DrcovData(cov_file.path)
            cov_input = pb.Input(filepath=cov_file.path.replace('.coverage', '.input'))
            stub.AddInput(cov_input)
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

            basic_blocks = map(google.protobuf.json_format.MessageToJson, basic_blocks)
            # https://docs.python.org/3.6/library/functions.html#zip
            edge_tuples = zip(*[iter(basic_blocks)]*cfg.coverage.number_of_addresses)
            edge_count = Counter(edge_tuples)
            edges = []
            def json_to_addr(json):
                return google.protobuf.json_format.Parse(json, pb.Address())
            
            for e in edge_count:
                msg_e = map(json_to_addr, e)
                edges.append(pb.EdgeCoverage(hit_count=edge_count[e], address=msg_e, input=cov_input))

            for r in stub.AddEdgeCoverage(iter(edges)):
                print(r.uuid)

            
if __name__ == '__main__':
    logging.basicConfig()
    run()
