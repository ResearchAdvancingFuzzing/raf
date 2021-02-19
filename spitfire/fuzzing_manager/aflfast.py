#
# Tm: A taint and coverage based fuzzing manager. 

#

from kubernetes import client, utils, config
import os
import glob
from os.path import basename
import yaml
import time
import subprocess
import random
import hydra
import logging
import grpc 
import sys
from pprint import pprint

# Get Environemnt variables 
namespace = os.environ.get("NAMESPACE")
spitfire_dir = "/%s%s" % (namespace, os.environ.get("SPITFIRE_DIR"))
corpus_dir = "/%s%s" % (namespace, os.environ.get("CORPUS_DIR"))
inputs_dir = "/%s%s" % (namespace, os.environ.get("INPUTS_DIR")) 
replays_dir = "/%s%s" % (namespace, os.environ.get("REPLAY_DIR"))
counts_dir = "/%s/counts" % namespace
target_dir = "/%s%s" % (namespace, os.environ.get("TARGET_INSTR_DIR"))

# Add to the python path for more imports
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(spitfire_dir + "/protos")
sys.path.append(spitfire_dir + "/utils")

import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg
import coverage
from kubernetes_help import * 


def calibrate_case(kbs, entry, queue_cycle, target):
    if entry.calibrated: 
        return

    #print(entry)
    # Execution time:
    start_time = time.time() * 1e6
    subprocess.run(args=[target, entry.filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stop_time = time.time() * 1e6
    exec_us = stop_time - start_time
    #print(exec_us)
    setattr(entry, "exec_time", exec_us)
    #print(inputs[file_name])

    # Bitmap size
    output_file = "out"
    cmd = "/AFL/afl-showmap -o %s  -- %s %s" % (output_file, target, entry.filepath)
    cmd = cmd.split()
    subprocess.run(args=cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = "wc -l %s" % output_file
    cmd = cmd.split()
    output = subprocess.check_output(args=cmd)
    bitmap_size = int(output.decode("utf-8").split()[0])
    setattr(entry, "bitmap_size", bitmap_size)
    #print(inputs[file_name])
    #print(bitmap_size)

    # Handicap value 
    setattr(entry, "handicap", 0 if queue_cycle == 0 else queue_cycle - 1)
    setattr(entry, "calibrated", True)
    kbs.AddInput(entry)
    old = kbs.GetInput(kbp.Input(filepath=entry.filepath))
    print(old)


def calculate_score(kbs, entry, avg_exec_time, avg_bitmap_size, fuzz_mu): 
    perf_score = 100
    print(entry)
    print(perf_score)
    print(avg_exec_time)
    print(avg_bitmap_size)
    print(fuzz_mu)
    print(entry.exec_time)
    
    # Adjust score based on execution speed of this path compared to global avg
    # Assign a greater perf_score if the execution time of the entry is less than 2x,3x,4x smaller
    # Assign a smaller perf_score if the execution time of the entry is more than 10x... greater 
    if entry.exec_time * 0.1 > avg_exec_time:
        perf_score = 10
    elif entry.exec_time * 0.25 > avg_exec_time:
        perf_score = 25
    elif entry.exec_time * 0.5 > avg_exec_time:
        perf_score = 50
    elif entry.exec_time * 0.75 > avg_exec_time:
        perf_score = 75
    elif entry.exec_time * 4 < avg_exec_time:
        perf_score = 300
    elif entry.exec_time * 3 < avg_exec_time:
        perf_score = 200
    elif entry.exec_time * 2 < avg_exec_time:
        perf_score = 150

    # Adjust score based on bitmap size
    # Increase perf_score if the bitmap size is more than 2x the avg ? 
    if entry.bitmap_size * 0.3 > avg_bitmap_size:
        perf_score *= 3
    elif entry.bitmap_size * 0.5 > avg_bitmap_size:
        perf_score *= 2
    elif entry.bitmap_size * 0.75 > avg_bitmap_size:
        perf_score *= 1.5 
    elif entry.bitmap_size * 3 < avg_bitmap_size:
        perf_score *= 0.25
    elif entry.bitmap_size * 2 < avg_bitmap_size:
        perf_score *= 0.5
    elif entry.bitmap_size * 1.5 < avg_bitmap_size:
        perf_score *= 0.75

    # handicap here
    if entry.handicap >= 4:
        perf_score *= 4
        #setattr(entry, "handicap", entry.handicap - 4)
    elif entry.handicap: 
        perf_score *= 2
        #setattr(entry, "handicap", entry.handicap - 1)
    kbs.AddInput(entry)

    # More power to inputs found further down 
    if entry.depth >= 0 or entry.depth < 4: # 0...3
        perf_score *= 2 
    elif entry.depth >= 4 or entry.depth < 8: # 4...7
        perf_score *= 3
    elif entry.depth >= 8 or entry.depth < 14: # 8...13
        perf_score *= 4 
    elif entry.depth >= 14 or entry.depth < 26: # 14...25
        perf_score *= 5

    # Parmaters 
    POWER_BETA = 1
    MAX_FACTOR = POWER_BETA * 32 
    HAVOC_MAX_MULT = 16 


    factor = 1
    fuzz = entry.n_fuzz
    schedule = "COE"
    if schedule == "EXPLORE": 
        pass
    elif schedule == "EXPLOIT": 
        factor = MAX_FACTOR
    elif schedule == "COE": 
        if fuzz <= fuzz_mu:
            if entry.fuzz_level < 16: 
                factor = 1 << entry.fuzz_level
            else:
                factor = MAX_FACTOR
        else:
            factor = 0
    elif schedule == "FAST": 
        if entry.fuzz_level < 16:
            factor = (1 << entry.fuzz_level) / 1 if fuzz == 0 else fuzz
        else:
            factor = MAX_FACTOR / 1 if fuzz == 0 else next_p2(fuzz) 
    elif schedule == "LIN": 
        factor = entry.fuzz_level / 1 if fuzz == 0 else fuzz 
    elif schedule == "QUAD":
        factor == entry.fuzz_level * entry.fuzz_level / 1 if fuzz == 0 else fuzz 
    else: 
        print("Power schedule unknown. Exiting.")
        exit(1)

    if factor > MAX_FACTOR:
        factor = MAX_FACTOR

    perf_score *= factor / POWER_BETA

    if perf_score > HAVOC_MAX_MULT * 100:
        perf_score = HAVOC_MAX_MULT * 100

    return perf_score 



@hydra.main(config_path=f"{spitfire_dir}/config/config.yaml")
def run(cfg):

    # Make sure the counts, inputs, replays directory exists
    if not os.path.exists(inputs_dir): 
        os.mkdir(inputs_dir) 
    if not os.path.exists(counts_dir):
        os.mkdir(counts_dir)

    # Compute budget 
    # so, like 10 cores or nodes or whatever
    budget = cfg.manager.budget
    target = "%s/%s" % (target_dir, cfg.target.name)

    # Setup job information
    job_names = ["taint", "coverage", "fuzzer"]
    jobs = {name:Job(name) for name in job_names}  
    #N = consult kubernetes to figure out how much many cores we are using currently

    # Setup access to cluster 
    config.load_incluster_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api() 

    # are any fm.py still running?
    # are any pods Pending?
    resp = core_v1.list_namespaced_pod(namespace=namespace)
    num_fm = 0
    num_pending = 0
    for i in resp.items:
        pt = i.spec.containers[0].image
        s = i.status.phase
        # number of running or pending fuzzing managers
        if (s=="Running" or s=="Pending") and "fm:" in pt:
            num_fm += 1
        if s=="Pending":
            num_pending += 1
    print ("num_fm = %d" % num_fm)

    if num_fm > 1:
        print ("A previous FM is still running -- exiting")
        return

    # Cleanup anything from before 
    for cj in batch_v1.list_namespaced_job(namespace=namespace, label_selector='tier=backend').items: 
        if not cj.status.active and cj.status.succeeded: 
            batch_v1.delete_namespaced_job(name=cj.metadata.name, namespace=namespace, propagation_policy="Background") 

    # Connect to the knowledge base 
    service = core_v1.list_namespaced_service(namespace=namespace) 
    ip = service.items[0].spec.cluster_ip
    port = service.items[0].spec.ports[0].port

    with grpc.insecure_channel('%s:%d' % (ip, port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        #S = set of original corpus seed inputs
        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
        print("%d Seeds" % (len(S)))
        
        #F = set of inputs we have done mutational fuzzing on so far
        F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
        print("%d Execution" % (len(F)))
        
        #C = set of inputs for which we have measured coverage
        C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}
        print("%d Inputs With Coverage" % (len(C)))
        
        #ICV = set of interesting inputs that got marginal covg (increased covg)
        ICV = {inp.uuid for inp in kbs.GetInputsWithoutCoverage(kbp.Empty())}
        print("%d Inputs without Coverage" % (len(ICV)))
        
        #T = set of inputs for which we have done taint analysis
        T = {inp.uuid for inp in kbs.GetTaintInputs(kbp.Empty())}
        print("%d Taint Inputs" % (len(T)))

        # set of inputs for which we have submitted jobs during this run
        # and thus results are pending
        # we need this so that we don't choose them again for analysis
        P = {inp.uuid for inp in kbs.GetPendingInputs(kbp.Empty())} #set([])
        print("%d Pending Inputs" % len(P))
            
        jobs_created = 0

        the_time = None
        
        # Add the seeds and interesting inputs to the queue
        # There is no ordering here?
        queue = S | ICV - P 
        print("\n\n\n\nStarting!")
        print(queue)
        print(len(queue))

        queue = [kbs.GetInputById(kbp.id(uuid=entry)) for entry in queue]

        # Calibrate data that has not yet been calibrated
        queue_cycle = min([entry.fuzz_level for entry in queue])
        print(queue_cycle)

        for entry in queue: 
            if not entry.calibrated:
                calibrate_case(kbs, entry, queue_cycle, target)

        # Parameters
        HAVOC_CYCLES_INIT = 1024
        HAVOC_CYCLES = 256 

        # Variables
        total_entries = len(queue)
        total_exec_time = 0
        total_bitmap_size = 0 
        total_fuzz = 0

        # Calculate averages  
        for entry in queue:
            #kb_inp = kbs.GetInputById(kbp.id(uuid=entry)) 
            total_exec_time += entry.exec_time 
            total_bitmap_size += entry.bitmap_size
            total_fuzz += entry.n_fuzz

        avg_exec_time = total_exec_time / total_entries
        avg_bitmap_size = total_bitmap_size / total_entries
        avg_fuzz_mu = total_fuzz / total_entries 
        print(avg_exec_time)
        print(avg_bitmap_size)
        print(avg_fuzz_mu)

        havoc_div = 1
        seed_avg_exec_time = sum([kbs.GetInputById(kbp.id(uuid=entry)).exec_time for entry in S]) / len(S) 
        print(seed_avg_exec_time)

        if seed_avg_exec_time > 50000:
            havoc_div = 10
        elif seed_avg_exec_time > 20000:
            havoc_div = 5
        elif seed_avg_exec_time > 10000:
            havoc_div = 2

        # let's sort this queue (based on f_i or s_i) 
        if False: #cfg.manager.search_strategy == "F"): # sorted based on low f_i (i.e. smallest number of fuzz)
            print("Sorting based on f_i") 
            queue = sorted(queue, key=lambda x: x.n_fuzz)
        else: # s(i) 
            print("Sorting based on s_i")
            queue = sorted(queue, key=lambda x: x.fuzz_level)

        index = 0
        while True:

            perf_score = calculate_score(kbs, queue[index], avg_exec_time, avg_bitmap_size, avg_fuzz_mu) 
            print(perf_score)

            if perf_score == 0: 
                index += 1
                continue # skip this entry

            stage_max = HAVOC_CYCLES * perf_score / havoc_div / 100
            print(queue[index])
            kb_inp = queue[index]

            # Run fuzzer with this input, stage_max times (-n arg) 
            job = jobs["fuzzer"]
            job.update_count_by(1) 
            args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_havoc.so", \
                    f"fuzzer.iteration_count={stage_max}", \
                    f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"] 
            print(args)
            try:
                fme = kbp.FuzzingManagerEvent(number=jobs_created, type=
                        kbp.FuzzingManagerEvent.Type.TAINT_FUZZ)
                kbs.AddFuzzingEvent(kbp.FuzzingEvent(fuzzing_manager_event=fme))
                kbs.MarkInputAsPending(kb_inp)
                create_job(cfg, batch_v1, "%s:%s" % (job.name, namespace), job.name, 
                        job.get_count(), args, namespace) 
                print ("uuid for input is %s" % (str(kb_inp.uuid)))
            except Exception as e:
               print("Unable to create job exception = %s" % str(e))

            break

            #index += 1

if __name__=="__main__":
    run()
