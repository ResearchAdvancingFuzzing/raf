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
interesting_dir = "%s/interesting/crash/" % work_dir 
coverage_dir = "%s/coverage" % work_dir

def copy_file(file_name, **arg):
    shutil.copy(file_name, arg["dest"])

def send_file(file_name, **arg):
    base_name = os.path.basename(file_name)
    file_name = "%s/%s" % (input_dir, base_name) 
    input_msg = kbp.Input(filepath=file_name, type=arg["kb_type"])
    input_kb = arg["kbs"].AddInput(input_msg) 

def perform_files(src, func, **arg): 
    src_files = os.listdir(src) 
    for file_name in src_files:
        full_file_name = os.path.join(src, file_name) 
        if os.path.isfile(full_file_name) and full_file_name.endswith(".input"):
            for a in arg.keys():
                print(a)
            func(full_file_name, **arg)
            #shutil.copy(full_file_name, dest)


@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):    
    
    target = "%s/%s" % (target_dir, cfg.target.name)
    fcfg = cfg.gtfo 

    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        
        print("here: connected")

        # Add the target, input, seed corpus, and experiment to the KB 
        kbs = kbpg.KnowledgeBaseStub(channel)
        input_msg = kbp.Input(filepath=fcfg.input_file)
        input_kb = kbs.AddInput(input_msg)
        #input_kb = kbs.GetInput(input_msg)
        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        #target_kb = kbs.GetTarget(target_msg)
        target_kb = kbs.AddTarget(target_msg)
        execution_msg = kbp.Execution(input=input_kb, target=target_kb)
        execution_kb = kbs.AddExecution(execution_msg)
        
        '''
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
        corpus = kbs.AddCorpus(corpus_msg)

        # experiment also needs a seed and a hash of the fuzzing manager 
        experiment_msg = kbp.Experiment(target=target, seed_corpus=corpus)
        experiment = kbs.AddExperiment(experiment_msg) 
        '''
    # Now let's fuzz

    # Move to the working directory  
    os.mkdir(work_dir)
    os.chdir(work_dir)
   
    # Get Config Information 
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
   
    if (os.path.isdir(interesting_dir)):
        perform_files(interesting_dir, copy_file, dest=input_dir)
    if (os.path.isdir(coverage_dir)):
        perform_files(coverage_dir, copy_file, dest=input_dir) 
    
    # Send new files over 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)
        kbp_covg_type = kbp.Input.InputType.COVG_INCREASED;
        kbp_interesting_type = kbp.Input.InputType.CRASH;
        if (os.path.isdir(interesting_dir)):
            perform_files(interesting_dir, send_file, kb_type=kbp_interesting_type, kbs=kbs)
        if (os.path.isdir(coverage_dir)):
            perform_files(coverage_dir, send_file, kb_type=kbp_covg_type, kbs=kbs)

if __name__ == '__main__':
    logging.basicConfig()
    run()
