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
import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg
import google.protobuf.json_format
import subprocess
import shutil
import hashlib

# Get the environment
work_dir = os.environ.get("WORK_DIR")
input_dir = os.environ.get("INPUTS_DIR")
gtfo_dir = os.environ.get("GTFO_DIR")
target_dir = os.environ.get("TARGET_DIR") 
spitfire_dir = os.environ.get("SPITFIRE")
corpus_dir = os.environ.get("CORPUS_DIR")

def copy_files(src, dest): 
    src_files = os.listdir(src) 
    for file_name in src_files:
        full_file_name = os.path.join(src, file_name) 
        if os.path.isfile(full_file_name) and full_file_name.endswith(".input"): 
            shutil.copy(full_file_name, dest)


@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):    
    
    target = "%s/%s" % (target_dir, cfg.target.name)
    
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        
        print("here: connected")

        # Add the target, input, seed corpus, and experiment to the KB 
        kbs = kbpg.KnowledgeBaseStub(channel)

        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        target_kb = kbs.AddTarget(target_msg) 
        
        fuzz_inputs = []
        uuid = []
        for dirpath,_,filenames in os.walk(corpus_dir): 
            for f in filenames:
                input_msg = kbp.Input(filepath=os.path.join(dirpath, f))
                fuzz_input = kbs.AddInput(input_msg)
                fuzz_inputs.append(fuzz_input)
                uuid.append(fuzz_input.uuid)
        uuid = b"".join(uuid)
        print(uuid)

        corpus_msg = kbp.Corpus(uuid=uuid, input=fuzz_inputs)
        #corpus = kbs.AddCorpus(corpus_msg)

        # experiment also needs a seed and a hash of the fuzzing manager 
        #experiment_msg = kbp.Experiment(target=target, seed_corpus=corpus)
        #experiment = kbs.AddExperiment(experiment_msg) 
    # Now let's fuzz

    # Move to the working directory  
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


if __name__ == '__main__':
    logging.basicConfig()
    run()
