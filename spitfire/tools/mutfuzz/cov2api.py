#import drcov
import logging
import grpc
import hydra
import os
import os.path
import sys
from collections import Counter
spitfire_dir= os.environ.get('SPITFIRE') #"/spitfire" # Env variable
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None)) 
import spitfire.protos.knowledge_base_pb2 as pb
import spitfire.protos.knowledge_base_pb2_grpc as rpc
import google.protobuf.json_format
import subprocess
import shutil

def copy_files(src, dest): 
    src_files = os.listdir(src) 
    for file_name in src_files:
        full_file_name = os.path.join(src, file_name) 
        if os.path.isfile(full_file_name) and full_file_name.endswith(".input"): 
            shutil.copy(full_file_name, dest)

@hydra.main(config_path="../../config/expt1/config.yaml")
def run(cfg):    
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
    #with grpc.insecure_channel('%s:%d' % ("10.105.43.27", 61111)) as channel:
        # Run the script here
        
        print("here: connected");
        # Setup environment variables 

        work_dir = os.environ.get("WORK_DIR")
        input_dir = os.environ.get("INPUTS_DIR")
        gtfo_dir = os.environ.get("GTFO_DIR")
        target_dir = os.environ.get("TARGET_DIR") 
        target = "%s/libxml2_instrumented/%s" % (target_dir, cfg.target.name)
        os.mkdir(work_dir)
        os.chdir(work_dir)
        
        # Get Config Information 
        fcfg = cfg.gtfo
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = f"{gtfo_dir}/gtfo/lib"
        env["JIG_TARGET"] = f"{target}"
        env["JIG_TARGET_ARGV"] = fcfg.jig.target_arg
        extra_args = fcfg.extra_args.split() 
        for arg in extra_args: 
            arg = arg.split("=")
            env[arg[0]] = arg[1]
        
        # Make the gtfo command 
        cmd = f'{gtfo_dir}/gtfo/bin/the_fuzz -S {gtfo_dir}/gtfo/gtfo/analysis/%s -O {gtfo_dir}/gtfo/gtfo/ooze/%s \
                -J {gtfo_dir}/gtfo/gtfo/the_fuzz/%s -i %s -n %d -x %d -c %s' % \
                (fcfg.analysis.name, fcfg.ooze.name, fcfg.jig.name, fcfg.input_file, fcfg.iteration_count, \
                fcfg.max_input_size, fcfg.analysis_load_file) 
        cmd = cmd.split()
        cmd += ["-s", fcfg.ooze_seed] 
        print(cmd) 

        # Run fuzzer 
        subprocess.run(args=cmd, env=env)

        # Move new input to /inputs directory 
        interesting_dir = "%s/interesting/crash/" % work_dir 
        coverage_dir = "%s/coverage" % work_dir
        
        if (os.path.isdir(interesting_dir)):
            copy_files(interesting_dir, input_dir)
        if (os.path.isdir(coverage_dir)):
            copy_files(coverage_dir, input_dir) 
        
        # We need to do coverage here
        
        stub = rpc.KnowledgeBaseStub(channel)
        print(os.listdir())
        print(os.getcwd())
        for cov_file in os.scandir(cfg.coverage.coverage_directory):
            #print("file")
            if not cov_file.is_file() or not cov_file.name.endswith('.input'):
                continue
            
            cov = drcov.DrcovData(cov_file.path)
            filepath = "%s/%s" % (input_dir, os.path.basename(cov_file.path)) #.replace('.coverage', '.input')))
            cov_input = pb.Input(filepath=filepath)
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
