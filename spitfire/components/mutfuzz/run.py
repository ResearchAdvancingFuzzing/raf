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
import struct 

# Get the environment
work_dir = os.environ.get("WORK_DIR")
input_dir = os.environ.get("INPUTS_DIR")
gtfo_dir = os.environ.get("GTFO_DIR")
target_dir = os.environ.get("TARGET_DIR") 
spitfire_dir = os.environ.get("SPITFIRE")
corpus_dir = os.environ.get("CORPUS_DIR")
interesting_dir = "%s/interesting/crash/" % work_dir 
coverage_dir = "%s/coverage" % work_dir


inputs = {} 

# Copy files from src to dest
# Add the attrb and value to that file 
def process_file(file_name, src, dest, attrb, value): 
    full_file_name = os.path.join(src, file_name) 
    # Anything we need to get from results?
    #if os.path.isfile(full_file_name) and full_file_name.endswith(".results"): 
    #    f = open(full_file_name, "rb").read()
    if os.path.isfile(full_file_name) and full_file_name.endswith(".input"):
        kb_input = None
        if not file_name in inputs: 
            shutil.copy(full_file_name, dest) 
            kb_input = kbp.Input(filepath = "%s/%s" % (dest, file_name))
            inputs[file_name] = kb_input
        setattr(inputs[file_name], attrb, value)

def process_files(src, dest, attrb, value): 
    if (os.path.isdir(src)): 
        src_files = os.listdir(src) 
        for i, file_name in enumerate(src_files):
            process_file(file_name, src, dest, attrb, value)


def send_to_database(kbs, inputs):
    # Inputs is a dictionary of inputs to their kb_input 
    kb_inputs = inputs.values()
    print("Sending %d new inputs to the database" % len(kb_inputs))
    for kb_input in kb_inputs:
        kbs.AddInput(kb_input) 

@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):    
    
    target = "%s/%s" % (target_dir, cfg.target.name)
    fcfg = cfg.gtfo 

    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        
        print("here: connected")

        # Add the target, input, seed corpus, and experiment to the KB 
        kbs = kbpg.KnowledgeBaseStub(channel)
        input_kb = kbs.GetInput(kbp.Input(filepath=fcfg.input_file))

        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        target_kb = kbs.AddTarget(target_msg)
        execution_msg = kbp.Execution(input=input_kb, target=target_kb)
        execution_kb = kbs.AddExecution(execution_msg)

        # TODO: Really we need for mutfuzz run.py to have the Experiment and Analysis
        # to add them to this fuzzing event
        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                              event=kbp.TimingEvent.Event.BEGIN)        
        kbs.AddFuzzingEvent(
            kbp.FuzzingEvent(input=input_kb.uuid,
                             timing_event=te))
        
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
    
    ooze_env_mod_name = "OOZE_MODULE_NAME"
    if ooze_env_mod_name in env:
        mod_name = env[ooze_env_mod_name]
        mod_name = f"{gtfo_dir}/gtfo/gtfo/ooze/{mod_name}" 
        env[ooze_env_mod_name] = mod_name
    
    # Make the gtfo command 
    cmd = f'{gtfo_dir}/gtfo/bin/the_fuzz -S {gtfo_dir}/gtfo/gtfo/analysis/%s -O {gtfo_dir}/gtfo/gtfo/ooze/%s \
            -J {gtfo_dir}/gtfo/gtfo/the_fuzz/%s -i %s -n %d -x %d -c %s' % \
            (fcfg.analysis.name, fcfg.ooze.name, fcfg.jig.name, fcfg.input_file, fcfg.iteration_count, \
            fcfg.max_input_size, fcfg.analysis_load_file) 
    cmd = cmd.split()
    cmd += ["-s", fcfg.ooze_seed] 
    print(cmd) 
    #return 
    # Run fuzzer 
    proc = subprocess.run(args=cmd, env=env)
    exit_code = proc.returncode

    process_files(coverage_dir, input_dir, "increased_coverage", 1)
    process_files(interesting_dir, input_dir, "crash", 1) 

    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        input_kb.fuzzed = True
        input_kb.pending_lock = False
        kb_input = kbs.AddInput(input_kb)
        
        send_to_database(kbs, inputs) 

        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                              event=kbp.TimingEvent.Event.END)        
        kbs.AddFuzzingEvent(
            kbp.FuzzingEvent(input=kb_input.uuid,
                             timing_event=te))


if __name__ == '__main__':
    logging.basicConfig()
    run()
