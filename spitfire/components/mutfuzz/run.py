import filecmp
import logging
import grpc
import hydra
import os
import os.path
import sys
from collections import Counter

# Env variables
namespace = os.environ.get("NAMESPACE") 
spitfire_dir = "/%s%s" % (namespace, os.environ.get('SPITFIRE_DIR')) 
input_dir = "/%s%s" % (namespace, os.environ.get('INPUTS_DIR'))
target_dir = "/%s%s" % (namespace, os.environ.get('TARGET_INSTR_DIR'))
corpus_dir = "/%s%s" % (namespace, os.environ.get('CORPUS_DIR'))
gtfo_dir = "/gtfo" #"/%s%s" % (namespace, os.environ.get('GTFO_DIR'))

# Add to path 
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")

import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg
import google.protobuf.json_format
import subprocess
import shutil
import hashlib
import struct 
from google.protobuf import text_format 

log = logging.getLogger(__name__)

inputs = {} 

# Copy files from src to dest
# Add the attrb and value to that file 
def process_file(file_name, src, dest, attrb, value): 
    full_file_name = os.path.join(src, file_name) 
    if os.path.isfile(full_file_name) and full_file_name.endswith(".input"):
        kb_input = None
        if not file_name in inputs: 
            shutil.copy(full_file_name, dest) 
            kb_input = kbp.Input(filepath = "%s/%s" % (dest, file_name))
            inputs[full_file_name] = kb_input
        setattr(inputs[full_file_name], attrb, value)

def process_files(input_file, src, dest, attrb, value): 
    if (os.path.isdir(src)): 
        src_files = os.listdir(src)
        for i, file_name in enumerate(src_files):
            ret = filecmp.cmp(input_file, os.path.join(src, file_name))
            if ret: 
                continue
            process_file(file_name, src, dest, attrb, value)


def send_to_database(kbs, inputs, kb_analysis, coverage_dir, interesting_dir):
    # Inputs is a dictionary of inputs to their kb_input 
    num_inc_covg = 0
    num_crash = 0
    for inp_path in inputs:
        inp = inputs[inp_path]
        result = kbs.InputExists(inp)
        #print(result.success)
        if not result.success: # Input did not exist before
            kb_input = kbs.AddInput(inp)
            # Add the fuzzing events
            if os.path.dirname(inp_path) == coverage_dir: # inc coverage
                num_inc_covg += 1
                te =  kbp.IncreasedCoverageEvent()        
                kbs.AddFuzzingEvent(kbp.FuzzingEvent(
                    analysis=kb_analysis.uuid, input=kb_input.uuid,
                    increased_coverage_event=te))
            if os.path.dirname(inp_path) == interesting_dir: # crashes
                num_crash += 1
                te = kbp.CrashEvent() 
                kbs.AddFuzzingEvent(kbp.FuzzingEvent(
                    analysis=kb_analysis.uuid, input=kb_input.uuid, 
                    crash_event=te))
        else: 
            kb_input = kbs.AddInput(inp)

    print("%d inputs that increased coverage" % num_inc_covg) 
    print("%d inputs that crashed" % num_crash) 
    print("Sent %d new inputs out of %d to the database" % 
            ((num_inc_covg+num_crash), len(inputs)))



def check_analysis_complete(cfg, kbs, inputfile):

    # get canonical representations for all of these things
    target_msg = kbp.Target(name=cfg.target.name, \
                            source_hash=cfg.target.source_hash)
    target = kbs.GetTarget(target_msg)
    
    gtfo_msg = kbp.AnalysisTool(name=cfg.fuzzer.name, \
                               source_string=cfg.fuzzer.source_string,
                               type=kbp.AnalysisTool.AnalysisType.MUTATION_FUZZER)
    gtfo     = kbs.AddAnalysisTool(gtfo_msg)

    print("input file is [%s]" % inputfile) 
    fuzzer_input = kbs.GetInput(kbp.Input(filepath=inputfile))

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


@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):    
    
    target = "%s/%s" % (target_dir, cfg.target.name)
    fcfg = cfg.fuzzer
    inputfile = fcfg.input_file

    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        
        print("here: connected")

        # Get the input
        kbs = kbpg.KnowledgeBaseStub(channel)
        input_kb = kbs.GetInput(kbp.Input(filepath=fcfg.input_file))

        # Get the target
        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        target_kb = kbs.GetTarget(target_msg)
        
        # Add the execution
        execution_msg = kbp.Execution(input=input_kb, target=target_kb)
        execution_kb = kbs.AddExecution(execution_msg)

        # Check if the analysis has already been performed
        [complete, kb_input, kb_analysis] = check_analysis_complete(cfg, kbs, inputfile)
        if complete:   
            return
        
        # TODO: Really we need for mutfuzz run.py to have the Experiment and Analysis
        # to add them to this fuzzing event
        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                              event=kbp.TimingEvent.Event.BEGIN)        
        kbs.AddFuzzingEvent(
            kbp.FuzzingEvent(
                analysis=kb_analysis.uuid,
                input=input_kb.uuid,
                             timing_event=te))
        
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
            (fcfg.analysis.name, fcfg.ooze.name, fcfg.jig.name, fcfg.input_file, fcfg.iteration_count, \
            fcfg.max_input_size, fcfg.analysis_load_file) 
    cmd = cmd.split()
    cmd += ["-s", fcfg.ooze_seed] 
    print(cmd) 

    # Run fuzzer 
    proc = subprocess.run(args=cmd, env=env)
    exit_code = proc.returncode
    
    interesting_dir = "%s/interesting/crash/" % os.getcwd()
    coverage_dir = "%s/coverage" % os.getcwd() 
    
    process_files(fcfg.input_file, coverage_dir, input_dir, "increased_coverage", 1)
    process_files(fcfg.input_file, interesting_dir, input_dir, "crash", 1) 

    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        input_kb.fuzzed = True
        input_kb.pending_lock = False
        kb_input = kbs.AddInput(input_kb)
        
        send_to_database(kbs, inputs, kb_analysis, coverage_dir, interesting_dir) 

        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                              event=kbp.TimingEvent.Event.END)        
        kbs.AddFuzzingEvent(
            kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
                input=kb_input.uuid,
                             timing_event=te))


if __name__ == '__main__':
    logging.basicConfig()
    run()
