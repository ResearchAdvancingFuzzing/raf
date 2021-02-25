
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
import random
from pprint import pprint

# Get Environemnt variables 
namespace = os.environ.get("NAMESPACE")
spitfire_dir = "/%s%s" % (namespace, os.environ.get("SPITFIRE_DIR"))
corpus_dir = "/%s%s" % (namespace, os.environ.get("CORPUS_DIR"))
inputs_dir = "/%s%s" % (namespace, os.environ.get("INPUTS_DIR")) 
replays_dir = "/%s%s" % (namespace, os.environ.get("REPLAY_DIR"))
counts_dir = "/%s/counts" % namespace
target_dir = "/%s%s" % (namespace, os.environ.get("TARGET_INSTR_DIR"))

trace_file_name = "%s/trace" % counts_dir
results_file_name = "%s/results" % counts_dir

# Add to the python path for more imports
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(spitfire_dir + "/protos")
sys.path.append(spitfire_dir + "/utils")

import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg
import coverage
from kubernetes_help import * 

# Mapping of bytes (ints) to entry uuids (string)
top_rated = {} 
# Mapping of uuids to lists representing the bytes they have seen so far
trace_bits_total = {}
score_changed = 0 

# Find first power of two greater or equal to value
def next_p2(value): 
    ret = 1
    while value > ret:
        ret = ret << 1
    return ret

# When we bump into a new path, we call this to see if the path appears
#  more "favorable" than any of the existing ones. 
def update_bitmap_score(kbs, entry, trace_bits): 
    global top_rated
    global score_changed

    print("updating bitmap score")
    fuzz_p2 = next_p2(entry.n_fuzz)
    fav_factor = entry.exec_time * entry.size 

    for path in trace_bits:  
        if path in top_rated: 
            top_rated_entry = kbs.GetInputById(kbp.id(uuid=top_rated[path]))
            top_rated_fuzz_p2 = next_p2(top_rated_entry.n_fuzz)
            top_rated_fav_factor = top_rated_entry.exec_time * entry.size
            if fuzz_p2 > top_rated_fuzz_p2: 
                continue
            elif fuzz_p2 == top_rated_fuzz_p2 and fav_factor > top_rated_fav_factor:
                continue

        # Looks like we are going to win this slot
        top_rated[path] = entry.uuid
        score_changed = 1

    #return score_changed

#  Finds and updates an input's exec time, bitmap size, and handicap (queue cycles behind) value 
def calibrate_case(kbs, entry, queue_cycle, target):
    global trace_bits_total 

    if entry.calibrated: 
        return
    print("calibrating case")
    print(entry)

    # Size 
    #setattr(entry, "size", os.path.getsize(entry.filepath))
    entry.size = os.path.getsize(entry.filepath)

    # Execution time:
    start_time = time.time() * 1e6
    subprocess.run(args=[target, entry.filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stop_time = time.time() * 1e6
    exec_us = stop_time - start_time
    #setattr(entry, "exec_time", exec_us)
    entry.exec_time = exec_us

    # Bitmap size and updating bitmap score
    output_file = "out"
    cmd = "/AFL/afl-showmap -o %s  -- %s %s" % (output_file, target, entry.filepath)
    cmd = cmd.split()
    subprocess.run(args=cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Open afl-showmap file to get path:count mapping
    f = open(output_file, "r") 
    trace_bits = {int(line.split(':')[0]):line.split(':')[1] for line in f.readlines()}
    trace_bits_total[entry.uuid] = trace_bits.keys()
    f.close()
    # We need to write it out also immediately
    
    # Number of bits set is just the length of that file 
    bitmap_size = len(trace_bits)
    #setattr(entry, "bitmap_size", bitmap_size)
    entry.bitmap_size = bitmap_size

    # Handicap value 
    #setattr(entry, "handicap", queue_cycle - 1) #0 if queue_cycle == 0 else queue_cycle - 1)
    entry.handicap = queue_cycle - 1
    print("Exec_time: %d, bitmap_size: %d, handicap: %d" % (exec_us, bitmap_size, queue_cycle - 1))

    update_bitmap_score(kbs, entry, trace_bits) 

    #setattr(entry, "calibrated", True)
    entry.calibrated = True
    kbs.AddInput(entry)
    print(entry)
    old = kbs.GetInput(kbp.Input(filepath=entry.filepath))
    print(old)



# Calculate case desirability score to adjust the length of havoc fuzzing (takes from AFLFast)
def calculate_score(cfg, kbs, entry, avg_exec_time, avg_bitmap_size, fuzz_mu): 
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
        setattr(entry, "handicap", entry.handicap - 4)
    elif entry.handicap: 
        perf_score *= 2
        setattr(entry, "handicap", entry.handicap - 1)
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
    POWER_BETA = cfg.manager.POWER_BETA 
    MAX_FACTOR = POWER_BETA * 32 
    HAVOC_MAX_MULT = cfg.manager.HAVOC_MAX_MULT

    factor = 1
    fuzz = entry.n_fuzz
    schedule = cfg.manager.schedule
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


# Looks at entire queue and returns a list of favored inputs 
def cull_queue(cfg, kbs, queue): 
    global score_changed
    print("SCORE_CHANGED %d" % score_changed)

    #if not score_changed:
    #    return 
    score_changed = 0
    pending_favored = 0
    favored = {}
    temp_v = [1 for i in range(0, cfg.manager.MAP_SIZE)]
    for path in sorted(top_rated): # all the top_rated entries we are looking at  
        #print("Path: %d, top_rated for path: %s, temp_v[path]: %d, trace_bits[entry]: " % (path, top_rated[path], temp_v[path]))
        #print(trace_bits_total[top_rated[path]]) 
        if not temp_v[path]: # if entry has seen a path we've already seen, continue
            continue
        uuid = top_rated[path]
        for index in trace_bits_total[uuid]: # if not, look at all paths it has seen and mark seen
            temp_v[index] = 0 
        favored[uuid] = 0
        entry = kbs.GetInputById(kbp.id(uuid=uuid)) 
        if entry.fuzz_level == 0: 
            pending_favored += 1 
    return [pending_favored, favored]
        

# Generate a random number between 0 and 100 
def UR(limit): 
    return random.randint(0, 99)

def skip_fuzz(cfg, kbs, pending_favored, favored, entry, queue, queue_cycle): 
    if pending_favored:
        if entry.fuzz_level > 0 or not entry.uuid in favored:
            if UR(100) < cfg.manager.SKIP_TO_NEW_PROB: 
                return 1
        elif not entry.uuid in favored and len(queue) > 10:
            if queue_cycle > 1 and entry.fuzz_level == 0:
                if UR(100) < cfg.manager.SKIP_NFAV_NEW_PROB:
                    return 1
            else: 
                if UR(100) < cfg.manager.SKIP_NFAV_OLD_PROB:
                    return 1
    return 0


@hydra.main(config_path=f"{spitfire_dir}/config/config.yaml")
def run(cfg):
    global top_rated
    global trace_bits_total

    # Make sure the counts, inputs directory exists
    if not os.path.exists(inputs_dir): 
        os.mkdir(inputs_dir) 
    if not os.path.exists(counts_dir):
        os.mkdir(counts_dir)
    
    # Let's get our data from files (top rated entries, bitmap traces)
    f = None
    try: 
        f = open(results_file_name, "r") 
        top_rated = {int(line.split(':')[0]):line.split(':')[1] for line in f.readlines()}
    except IOError:
        top_rated = {}
    finally: 
        if f:
            f.close()
    print(top_rated)

    # Let's get our input bitmap traces 
    f = None
    try:
        f = open(trace_file_name, "r") 
        trace_bits_total = {} 
        for line in f.readlines(): 
            tup = line.rstrip().split(':')
            trace_bits_total[tup[0]] = [int(x) for x in tup[1].split(',')] 
    except IOError:
        trace_bits_total = {}
    finally: 
        if f:
            f.close() 
    print(trace_bits_total)

    # Compute budget 
    budget = cfg.manager.budget
    target = "%s/%s" % (target_dir, cfg.target.name)

    # Setup job information
    job_names = ["fuzzer"]
    jobs = {name:Job(name) for name in job_names}  

    # Setup access to cluster 
    config.load_incluster_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api() 

    # Status of current fuzzing manager; cleanup old jobs
    if num_active_fm(namespace) > 1: 
        print ("A previous FM is still running -- exiting")
        #return
    cleanup_finished_jobs(namespace) 

    # Connect to the knowledge base 
    service = core_v1.list_namespaced_service(namespace=namespace) 
    ip = service.items[0].spec.cluster_ip
    port = service.items[0].spec.ports[0].port

    with grpc.insecure_channel('%s:%d' % (ip, port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        #S = set of original corpus seed inputs
        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
        print("%d Seeds" % (len(S)))

        ''' 
        # set of inputs that are unfinished, with results still pending  
        P = {inp.uuid for inp in kbs.GetPendingInputs(kbp.Empty())} #set([])
        print("%d Pending Inputs" % len(P))
        '''

        # Parameters (taken from AFLFast)
        HAVOC_CYCLES_INIT = cfg.manager.HAVOC_CYCLES_INIT 
        HAVOC_CYCLES = cfg.manager.HAVOC_CYCLES

        # Adjust havoc_div (cycle count divisor for havoc)
        havoc_div = 1
        seed_avg_exec_time = sum([kbs.GetInputById(kbp.id(uuid=entry)).exec_time for entry in S]) / len(S) 
        print(seed_avg_exec_time)
        if seed_avg_exec_time > 50000:
            havoc_div = 10
        elif seed_avg_exec_time > 20000:
            havoc_div = 5
        elif seed_avg_exec_time > 10000:
            havoc_div = 2
        print(havoc_div)

        total_exec_time, total_bitmap_size, total_fuzz = 0, 0, 0
        new_inp_index = 0
        skipped_fuzz = False

        while True:
            # Only do this part if we have not skipped the last fuzz
            if not skipped_fuzz: 
                # Get the queue and the queue cycle 
                queue = [kbs.GetInputById(kbp.id(uuid=inp.uuid)) for inp in kbs.GetQueue(kbp.Empty())]
                queue_cycle = kbs.GetQueueCycle(kbp.Empty()).val 
                total_entries = len(queue)
                print("Queue len: %d, Queue cycle: %d, New_index: %d" % (len(queue), queue_cycle, new_inp_index))
                print(queue)

                # Calibrate things in the queue that have not yet been calibrated
                # Calculate totals AFTER calibration
                start = time.time()
                for i in range(new_inp_index, len(queue)):
                    #print(queue[i])
                    #print("here")
                    #print(kbs.GetInputById(kbp.id(uuid=queue[i].uuid)))
                    if not queue[i].calibrated: 
                        calibrate_case(kbs, queue[i], queue_cycle, target)
                    total_exec_time += queue[i].exec_time 
                    total_bitmap_size += queue[i].bitmap_size
                    total_fuzz += queue[i].n_fuzz
                stop = time.time()

                print("Time: %d for %d inp" % (stop-start, total_entries))
                # Calculate averages from totals
                avg_exec_time = total_exec_time / total_entries
                avg_bitmap_size = total_bitmap_size / total_entries
                avg_fuzz_mu = total_fuzz / total_entries 
                print("Avg_exec_time: %d, avg_bitmap_size: %d, avg_fuzz_mu: %d" % (avg_exec_time, avg_bitmap_size, avg_fuzz_mu))

                start = time.time()
                [pending_favored, favored] = cull_queue(cfg, kbs, queue) 
                stop = time.time()
                print("Cull queue time: %d")
                print(stop-start)
                print("Pending favored: %d" % pending_favored)
                print("Favored:") 
                print(favored)

            # Get the next input in the queue
            kb_inp = kbs.NextInQueue(kbp.Empty()) 
            print("INPUT_TO_FUZZ")
            print(kb_inp)

            # Skip this input with some probability if it is not favored
            skipped_fuzz = skip_fuzz(cfg, kbs, pending_favored, favored, kb_inp, queue, queue_cycle) 
            if skipped_fuzz: 
                print("skipped_fuzz 1") 
                return
                #continue

            # Calculate the score of that input for potential havoc fuzzing
            start = time.time()
            perf_score = calculate_score(cfg, kbs, kb_inp, avg_exec_time, avg_bitmap_size, avg_fuzz_mu) 
            stop = time.time()
            print(stop-start)
            print(perf_score)

            if perf_score == 0: 
                skipped_fuzz = True
                print("skipped_fuzz 2") 
                return
                #continue # skip this entry

            # We are fuzzing
            new_inp_index = len(queue)

            # Calculate how many iterations to fuzz (AFLFast)
            stage_max = HAVOC_CYCLES * perf_score / havoc_div / 100
            print("Stage_max: %d" % stage_max)

            # Run fuzzer with this input, stage_max times (-n arg) 
            job = jobs["fuzzer"]
            job.update_count_by(1) 
            args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_havoc.so", \
                    f"fuzzer.iteration_count={stage_max}", \
                    f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"] 
            print(args)
            try:
                kbs.MarkInputAsPending(kb_inp)
                create_job(cfg, batch_v1, "%s:%s" % (job.name, namespace), job.name, 
                        job.get_count(), args, namespace) 
                print ("uuid for input is %s" % (str(kb_inp.uuid)))
            except Exception as e:
               print("Unable to create job exception = %s" % str(e))

            break

        # Save results
        f = open(results_file_name, "w") 
        print(top_rated)
        for path in top_rated:
            f.write("{}:{}\n".format(path, top_rated[path]))
        f.close()

        f = open(trace_file_name, "w")
        print(trace_bits_total)
        for uuid in trace_bits_total:
            f.write("{}:".format(uuid))
            for path in trace_bits_total[uuid]: 
                f.write(str(path))
                if path  != trace_bits_total[uuid][-1]: 
                    f.write(",")
                else:
                    f.write("\n")
        f.close()


if __name__=="__main__":
    run()
