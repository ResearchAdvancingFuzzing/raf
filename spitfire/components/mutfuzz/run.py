import filecmp
import logging
import grpc
import hydra
import os
import os.path
import sys
import time
from collections import Counter
from kubernetes import client, config
# Env variables
namespace = os.environ.get("NAMESPACE") 
spitfire_dir = "/%s%s" % (namespace, os.environ.get('SPITFIRE_DIR')) 
input_dir = "/%s%s" % (namespace, os.environ.get('INPUTS_DIR'))
target_dir = "/%s%s" % (namespace, os.environ.get('TARGET_INSTR_DIR'))
corpus_dir = "/%s%s" % (namespace, os.environ.get('CORPUS_DIR'))
gtfo_dir = "/gtfo" #"/%s%s" % (namespace, os.environ.get('GTFO_DIR'))
counts_dir = "/%s/counts" % namespace

# Add to path 
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")
sys.path.append(spitfire_dir + "/utils")

import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg
import google.protobuf.json_format
import subprocess
import shutil
import hashlib
import struct 
from google.protobuf import text_format 

log = logging.getLogger(__name__)

inputs = {} # tracks all the new interesting inputs (file_name, kb_input) 


# Copy all files in src to dest 
def copy_to_shared_dir(src, dest): 
    if not os.path.isdir(src) or not os.path.isdir(dest):
        return 
    src_files = os.listdir(src) 
    for i, file_name in enumerate(src_files): 
        full_file_name = os.path.join(src, file_name) 
        if not os.path.isfile(full_file_name):
            continue
        shutil.copy(full_file_name, dest)

# Adds any attributes specified in attrib_map, plus main ones
def add_attrib_to_inp(kb_inp, attrib_map, depth): 
    for attrib, value in attrib_map.items(): 
        setattr(kb_inp, attrib, value)
    kb_inp.depth = depth
    kb_inp.time_found = time.time()
    kb_inp.n_fuzz = 0
    kb_inp.fuzz_level = 0
    

# Helper function for send_to_database
# Sends the input to the KB
def add_inp_to_database(kbs, file_name, attrib_map, depth): 
    new_inp= kbp.Input(filepath = "%s/%s" % (input_dir, file_name)) # create the kb input for this 
    result = kbs.InputExists(new_inp)
    if result.success: # Exists
        was_new = False 
        # Let's update the input with the one in the db
        new_inp = kbs.GetInput(new_inp)
        #if new_kb_input.seed: # input exists
        #old_base = os.path.splitext(file_name)[0]
        #new_base = os.path.basename(os.path.splitext(new_kb_input.filepath)[0])
        #results = "%s/%s.results" % (input_dir, old_base)
        #new_results = "%s/%s.results" % (input_dir, new_base)
        #os.rename(results, new_results) 
    add_attrib_to_inp(new_inp, attrib_map, depth)
    new_kb_input = kbs.AddInput(new_inp)
    return new_kb_input


def send_to_database(kbs, kb_input, kb_analysis, coverage_dir, interesting_dir):
    # Inputs is a dictionary of inputs to their kb_input 
    num_inc_covg = 0
    num_crash = 0
    depth = kb_input.depth + 1

    # Add the new interesting inputs to the KB 
    files_in_both = [] 
    interesting_files = os.listdir(interesting_dir) if os.path.isdir(interesting_dir) else []
    interesting_files = {f:1 for f in interesting_files}
    covg_files = os.listdir(coverage_dir) if os.path.isdir(coverage_dir) else []
    covg_files = {f:1 for f in covg_files} 

    # Files in both
    for file_name in interesting_files.keys():
        if file_name in covg_files:
            new_kb_input = add_inp_to_database(kbs, file_name, {"crash":1, "increased_coverage":1}, depth) 
            crash_event, ic_event = kbp.CrashEvent(), kbp.IncreasedCoverageEvent()
            kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid,  
                input=new_kb_input.uuid, crash_event=crash_event))
            kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid,  
                input=new_kb_input.uuid, increased_coverage_event=ic_event))

            kbs.AddToQueue(new_kb_input)

    # Files in crash
    for file_name in interesting_files.keys(): 
        if not file_name.endswith(".input"):
            continue
        new_kb_input = add_inp_to_database(kbs, file_name, {"crash": 1}, depth)
        #if new_kb_input: # and was_new:
        num_crash += 1
        event = kbp.CrashEvent()
        kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid,  
            input=new_kb_input.uuid, crash_event=event))

    # Files in increased covg
    for file_name in covg_files.keys():
        if not file_name.endswith(".input"): 
            continue 
        new_kb_input = add_inp_to_database(kbs, file_name, {"increased_coverage": 1}, depth) 
        #if new_kb_input and was_new:
        num_inc_covg += 1
        event = kbp.IncreasedCoverageEvent()
        kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid,  
            input=new_kb_input.uuid, increased_coverage_event=event))

        # Add to the queue
        kbs.AddToQueue(new_kb_input) 

    # Update the input we fuzzed 
    kb_input.fuzzed = True
    kb_input.pending_lock = False
    n_fuzz = kb_input.n_fuzz + num_inc_covg
    #fuzz_level = kb_input.fuzz_level + 1 
    kb_input.n_fuzz = n_fuzz
    #kb_input.fuzz_level = fuzz_level
    #print(kb_input) 
    kb_input = kbs.AddInput(kb_input)
    kb_input = kbs.GetInput(kb_input)
    # Print some stuff out
    print(kb_input)
    #print("N_fuzz: %d Fuzz_level: %d" % (n_fuzz, fuzz_level))
    print("%d inputs that increased coverage" % num_inc_covg) 
    print("%d inputs that crashed" % num_crash) 



def check_analysis_complete(cfg, kbs, input_file):

    # get canonical representations for all of these things
    target_msg = kbp.Target(name=cfg.target.name, \
                            source_hash=cfg.target.source_hash)
    target = kbs.GetTarget(target_msg)
    
    gtfo_msg = kbp.AnalysisTool(name=cfg.fuzzer.name, \
                               source_string=cfg.fuzzer.source_string,
                               type=kbp.AnalysisTool.AnalysisType.MUTATION_FUZZER)
    gtfo     = kbs.AddAnalysisTool(gtfo_msg)

    print("input file is [%s]" % input_file) 
    fuzzer_input = kbs.GetInput(kbp.Input(filepath=input_file))

    # if we have already performed this coverage analysis, bail
    fuzzer_analysis_msg = kbp.Analysis(tool=gtfo.uuid, \
                                      target=target.uuid, \
                                      input=fuzzer_input.uuid)
    fuzzer_analysis = kbs.AddAnalysis(fuzzer_analysis_msg)


    msg_end =  "\ntool[%s]\ntarget[%s]\ninput[%s]" \
          % (text_format.MessageToString(gtfo), \
             text_format.MessageToString(target), \
             text_format.MessageToString(fuzzer_input))
    
    if fuzzer_analysis.complete:
        log.info("Fuzzer analysis already performed for %s" % msg_end)
        return [True, None, fuzzer_analysis]
    
    log.info("Fuzzer analysis proceeding for %s" % msg_end)
    return [False, fuzzer_input, fuzzer_analysis] 


@hydra.main(config_path=f"{spitfire_dir}/config", config_name="config")
def run(cfg):    
    
    target = "%s/%s" % (target_dir, cfg.target.name)
    fcfg = cfg.fuzzer
    input_file = fcfg.input_file

    # Setup access to cluster 
    config.load_incluster_config()
    core_api = client.CoreV1Api()
    service = core_api.list_namespaced_service(namespace=namespace)
    ip = service.items[0].spec.cluster_ip
    port = service.items[0].spec.ports[0].port
    
    # Send over some preliminary data to check if we have done this taint before 
    with grpc.insecure_channel('%s:%d' % (ip, port)) as channel:
        
        print("here: connected")

        # Get the input
        kbs = kbpg.KnowledgeBaseStub(channel)
        kb_input = kbs.GetInput(kbp.Input(filepath=input_file))
        print(kb_input)

        # Get the target
        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        target_kb = kbs.GetTarget(target_msg)
        
        # Add the execution
        execution_msg = kbp.Execution(input=kb_input, target=target_kb)
        execution_kb = kbs.AddExecution(execution_msg)

        # Check if the analysis has already been performed
        [complete, kb_input, kb_analysis] = check_analysis_complete(cfg, kbs, input_file)
        if complete:   
            return
        
        # TODO: Really we need for mutfuzz run.py to have the Experiment and Analysis
        # to add them to this fuzzing event
        te = kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                event=kbp.TimingEvent.Event.BEGIN)        
        kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
            input=kb_input.uuid, timing_event=te))
        
    # Now let's fuzz
   
    # Get Config Information 
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{gtfo_dir}/lib"
    print(target)
    env["JIG_TARGET"] = f"{target}"
    env["JIG_TARGET_ARGV"] = fcfg.jig.target_arg
    extra_args = fcfg.extra_args.split() 
    for arg in extra_args: 
        arg = arg.split("=")
        env[arg[0]] = arg[1]
    
    ooze_env_mod_name = "OOZE_MODULE_NAME"
    if ooze_env_mod_name in env:
        mod_name = env[ooze_env_mod_name]
        mod_name = f"{gtfo_dir}/gtfo/ooze/{mod_name}" 
        env[ooze_env_mod_name] = mod_name
    
    # Make the gtfo command 
    cmd = f'{gtfo_dir}/bin/the_fuzz -S {gtfo_dir}/gtfo/analysis/%s -O {gtfo_dir}/gtfo/ooze/%s \
            -J {gtfo_dir}/gtfo/the_fuzz/%s -i %s -n %d -x %d -c %s' % \
            (fcfg.analysis.name, fcfg.ooze.name, fcfg.jig.name, input_file, fcfg.iteration_count, \
            fcfg.max_input_size, fcfg.analysis_save_file) 
    cmd = cmd.split()
    cmd += ["-s", fcfg.ooze_seed] 
    if os.path.isfile(fcfg.analysis_load_file): 
        cmd += ["-C", fcfg.analysis_load_file] 
    print(cmd) 

    # Run fuzzer
    proc = subprocess.run(args=cmd, env=env)
    exit_code = proc.returncode
    
    # Process the results
    result_bitmap = f"{os.getcwd()}/{fcfg.analysis_save_file}" 
    shutil.copyfile(result_bitmap, f"{counts_dir}/bitmap_{os.path.basename(input_file)}_{fcfg.job_number}")

    interesting_dir = "%s/interesting/crash/" % os.getcwd()
    coverage_dir = "%s/coverage" % os.getcwd() 
    
    copy_to_shared_dir(coverage_dir, input_dir)
    copy_to_shared_dir(interesting_dir, input_dir)

    # Reconnect to the database to send some stuff over 
    with grpc.insecure_channel('%s:%d' % (ip, port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)
        
        send_to_database(kbs, kb_input,  kb_analysis, coverage_dir, interesting_dir) 

        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                              event=kbp.TimingEvent.Event.END)        
        kbs.AddFuzzingEvent(
            kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
                input=kb_input.uuid,
                             timing_event=te))


if __name__ == '__main__':
    logging.basicConfig()
    run()
