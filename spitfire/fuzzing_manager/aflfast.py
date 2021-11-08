
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

# Mapping of ints (bytes/paths) to inputs
total_execs = 0
top_rated = {} 
# Mapping of uuids to lists representing the bytes they have seen so far
trace_bits_total = {}
score_changed = 0 
pending_favored = 0
favored = {} 

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

    fuzz_p2 = next_p2(entry.n_fuzz)
    fav_factor = entry.exec_time * entry.size 

    for path in trace_bits:  
        if path in top_rated: 
            top_rated_entry = top_rated[path]
            top_rated_fuzz_p2 = next_p2(top_rated_entry.n_fuzz)
            top_rated_fav_factor = top_rated_entry.exec_time * entry.size
            if fuzz_p2 > top_rated_fuzz_p2: 
                continue
            elif fuzz_p2 == top_rated_fuzz_p2 and fav_factor > top_rated_fav_factor:
                continue

        # Looks like we are going to win this slot
            
        top_rated[path] = entry
        score_changed = 1


#  Finds and updates an input's exec time, bitmap size, and handicap (queue cycles behind) value 
def calibrate_case(kbs, entry, queue_cycle, target):
    global trace_bits_total 
    global total_execs

    if entry.calibrated: 
        return

    total_execs += 1

    # Size 
    entry.size = os.path.getsize(entry.filepath)

    # Execution time:
    start_time = time.time() * 1e6
    subprocess.run(args=[target, entry.filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stop_time = time.time() * 1e6
    exec_us = stop_time - start_time
    entry.exec_time = exec_us
    #print("Execution_time {}".format(exec_us / 1e6))

    # Bitmap size and updating bitmap score
    start_time = time.time()
    output_file = "out"
    cmd = "/AFL/afl-showmap -o %s  -- %s %s" % (output_file, target, entry.filepath)
    cmd = cmd.split()
    subprocess.run(args=cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stop_time = time.time()
    #print("Afl-showmap time: {}".format(stop_time-start_time))

    # Open afl-showmap file to get path:count mapping
    start_time = time.time()
    f = open(output_file, "r") 
    trace_bits = {int(line.split(':')[0]):line.split(':')[1] for line in f.readlines()}
    trace_bits_total[entry.uuid] = list(trace_bits.keys())
    f.close()
    stop_time = time.time()
    #print("Process trace_bits time : {}".format(stop_time-start_time))
    
    # Number of bits set is just the length of that file 
    bitmap_size = len(trace_bits)
    entry.bitmap_size = bitmap_size

    # Handicap value 
    entry.handicap = queue_cycle - 1

    start = time.time()
    update_bitmap_score(kbs, entry, trace_bits) 
    stop = time.time()
    #print("Update bitmap score time: {}".format(stop-start))

    entry.calibrated = True
    kbs.AddInput(entry)
    #print(entry)
    #old = kbs.GetInput(kbp.Input(filepath=entry.filepath))
    #print(old)



# Calculate case desirability score to adjust the length of havoc fuzzing (takes from AFLFast)
def calculate_score(cfg, kbs, entry, avg_exec_time, avg_bitmap_size, fuzz_mu): 
    perf_score = 100
    
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
    global top_rated
    global trace_bits_total 
    global score_changed
    global pending_favored
    global favored

    print("Score_changed %d" % score_changed)
    if not score_changed:
        return
    print("Culling queue")

    score_changed = 0
    pending_favored = 0
    favored = {}
    temp_v = [1 for i in range(0, cfg.manager.MAP_SIZE)]
    for path in sorted(top_rated): # all the top_rated entries we are looking at  
        if not temp_v[path]: # if entry has seen a path we've already seen, continue
            continue
        uuid = top_rated[path].uuid
        for index in trace_bits_total[uuid]: # if not, look at all paths it has seen and mark seen
            temp_v[index] = 0 
        favored[uuid] = 0
        entry = kbs.GetInputById(kbp.id(uuid=uuid)) 
        if entry.fuzz_level == 0: 
            pending_favored += 1 
    return
        

# Generate a random number between 0 and 100 
def UR(limit): 
    return random.randint(0, 99)

# Determine if we will fuzz entry
def skip_fuzz(cfg, kbs, entry, queue, queue_cycle): 
    global pending_favored
    global favored

    if pending_favored:
        if entry.fuzz_level > 0 or not entry.uuid in favored:
            if UR(100) < cfg.manager.SKIP_TO_NEW_PROB: 
                return True
        elif not entry.uuid in favored and len(queue) > 10:
            if queue_cycle > 1 and entry.fuzz_level == 0:
                if UR(100) < cfg.manager.SKIP_NFAV_NEW_PROB:
                    return True
            else: 
                if UR(100) < cfg.manager.SKIP_NFAV_OLD_PROB:
                    return True
    return False


def get_file_data(): 
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

    # Let's get our input bitmap traces 
    f = None
    try:
        f = open(trace_file_name, "r") 
        trace_bits_total = {} 
        for line in f.readlines(): 
            tup = line.rstrip().split(':')
            trace_bits_total[tup[0].encode("utf-8")] = [int(x) for x in tup[1].split(',')] 
    except IOError:
        trace_bits_total = {}
    finally: 
        if f:
            f.close() 

def save_data_file():
    global top_rated
    global trace_bits_total 

    # Save results
    f = open(results_file_name, "w") 
    for path in top_rated:
        string_id = (top_rated[path].uuid).decode("utf-8")
        f.write("{}:{}\n".format(path, string_id))
    f.close()

    f = open(trace_file_name, "w")
    for uuid in trace_bits_total:
        f.write("{}:".format(uuid.decode("utf-8")))
        for path in trace_bits_total[uuid]: 
            f.write(str(path))
            if path  != trace_bits_total[uuid][-1]: 
                f.write(",")
            else:
                f.write("\n")
    f.close()

def deterministic_fuzz(cfg, kb_inp, job, bitmap_file):

    # Run deterministic fuzzing 
    # Afl bit flip
    job.update_count_by(1) 
    args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_bit_flip.so", \
            f"fuzzer.analysis_load_file={bitmap_file}", \
            f"fuzzer.job_number={job.get_count()}", \
            f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"]  
    create_job(cfg, "%s:%s" % (job.name, namespace), job.name, job.get_count(), args, namespace) 
    
    # AFL arith
    job.update_count_by(1) 
    args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_arith.so", \
            f"fuzzer.analysis_load_file={bitmap_file}", \
            f"fuzzer.job_number={job.get_count()}", \
            f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"]  
    create_job(cfg, "%s:%s" % (job.name, namespace), job.name, job.get_count(), args, namespace) 

    # AFL interest
    job.update_count_by(1) 
    args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_interesting.so", \
            f"fuzzer.analysis_load_file={bitmap_file}", \
            f"fuzzer.job_number={job.get_count()}", \
            f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"]  
    create_job(cfg, "%s:%s" % (job.name, namespace), job.name, job.get_count(), args, namespace) 

    # AFL dictionary
    job.update_count_by(1) 
    args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_dictionary.so", \
            f"fuzzer.analysis_load_file={bitmap_file}", \
            f"fuzzer.job_number={job.get_count()}", \
            f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"]  
    create_job(cfg, "%s:%s" % (job.name, namespace), job.name, job.get_count(), args, namespace) 


@hydra.main(config_path=f"{spitfire_dir}/config/config.yaml")
def run(cfg):


    global top_rated
    global trace_bits_total
    global pending_favored
    global favored
    global total_execs
    
    start_time_1 = time.time()

    # Setup access to cluster 
    config.load_incluster_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api() 
    #cluster_usages(True)
    
    # Check if other fuzzing managers are alive 
    # If more than 2 are, stop 
    if active_fm(namespace) > 2:
        print("Too many fm, returning")
        return

    # If only 2 are, then wait until the other finishes 
    while active_fm(namespace) > 1: 
        pass
    
    start_time_2 = time.time()
    cleanup_finished_jobs(namespace) 

    get_file_data()

    # Compute budget 
    max_pods = cfg.manager.max_pods
    target = "%s/%s" % (target_dir, cfg.target.name)

    # Setup job information
    job_names = ["fuzzer"]
    jobs = {name:Job(name) for name in job_names}  

    # Connect to the knowledge base 
    service = core_v1.list_namespaced_service(namespace=namespace) 
    ip = service.items[0].spec.cluster_ip
    port = service.items[0].spec.ports[0].port

    with grpc.insecure_channel('%s:%d' % (ip, port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 

        # Replace top rated uuids with actual entries 
        top_rated = {key:kbs.GetInputById(kbp.id(uuid=val.rstrip("\n").encode("utf-8"))) \
                for key,val in top_rated.items()} 

        # Parameters (taken from AFLFast)
        HAVOC_CYCLES_INIT = cfg.manager.HAVOC_CYCLES_INIT 
        HAVOC_CYCLES = cfg.manager.HAVOC_CYCLES
        HAVOC_MAX_MULT = cfg.manager.HAVOC_MAX_MULT

        # Adjust havoc_div (cycle count divisor for havoc)
        havoc_div = 1
        seed_avg_exec_time = sum([kbs.GetInputById(kbp.id(uuid=entry)).exec_time \
                for entry in S]) / len(S) 
        if seed_avg_exec_time > 50000:
            havoc_div = 10
        elif seed_avg_exec_time > 20000:
            havoc_div = 5
        elif seed_avg_exec_time > 10000:
            havoc_div = 2
        print("Havoc div: %d" % havoc_div)

        total_exec_time, total_bitmap_size, total_fuzz = 0, 0, 0
        new_inp_index = 0
        jobs_created = 0
        queue = []
        
        end_time = time.time()
        print(f"Took {start_time_2-start_time_1} seconds to wait and"
        f"{end_time-start_time_2} to init process.")
        while True:

            skipped_fuzz = False

            # If another fm is waiting for us to finish, 
            # stop so they can begin 
            if active_fm(namespace) > 1: 
                break

            # If we have already created the max amount of pods
            # wait until some finish to create more
            while take_stock() >= max_pods:
                pass

            if active_fm(namespace) > 1:
                break
            
            start_time = time.time()
            # Only do this part if we have not skipped the last fuzz
            if not skipped_fuzz: 
                # Get the queue and the queue cycle 
                start_time_a = time.time()
                queue = [inp for inp in kbs.GetQueue(kbp.Empty())]
                queue_len = len(queue)
                queue_cycle = kbs.GetQueueCycle(kbp.Empty()).val 
                total_entries = queue_len 
                print(f"Queue len: {len(queue)}, Queue cycle: {queue_cycle}, " 
                        f"New_index: {new_inp_index}")

                start_time_b = time.time()
                calibrated = 0
                # Calibrate things in the queue that have not yet been calibrated
                for i in range(new_inp_index, len(queue)):
                    if not queue[i].calibrated: 
                        calibrated += 1
                        calibrate_case(kbs, queue[i], queue_cycle, target)
                    total_exec_time += queue[i].exec_time 
                    total_bitmap_size += queue[i].bitmap_size
                    total_fuzz += queue[i].n_fuzz

                start_time_c = time.time()
                # Calculate averages from totals
                avg_exec_time = total_exec_time / total_entries
                avg_bitmap_size = total_bitmap_size / total_entries
                avg_fuzz_mu = total_fuzz / total_entries 
                print(f"Avg_exec_time: {avg_exec_time}, avg_bitmap_size:" 
                        f"{avg_bitmap_size}, avg_fuzz_mu: {avg_fuzz_mu}")
            
                start_time_d = time.time()
                cull_queue(cfg, kbs, queue) 
                print(f"Pending favored: {pending_favored}\nFavored: {len(favored)}")
            
            end_time = time.time()
            print(f"Took {start_time_b - start_time_a} for getting queue, "
                    f"{start_time_c - start_time_b} for calibration of {calibrated} inputs, "
                    f"{start_time_d - start_time_c} for culling.")
            print(f"Took {end_time-start_time} seconds to process round {jobs_created}.")

            if active_fm(namespace) > 1:
                break

            if jobs_created > 0 and queue_len < 10:
                continue

            # Get the next input in the queue
            kb_inp = kbs.NextInQueue(kbp.Empty())

            # Skip this input with some probability if it is not favored
            skipped_fuzz = skip_fuzz(cfg, kbs, kb_inp, queue, queue_cycle) 
            if skipped_fuzz: 
                print(f"skipped_fuzz 1: {kb_inp.uuid}")
                continue

            # Calculate the score of that input for potential havoc fuzzing
            perf_score = calculate_score(cfg, kbs, kb_inp, avg_exec_time, 
                    avg_bitmap_size, avg_fuzz_mu) 
            print(f"Score for input: {perf_score}")

            if perf_score == 0: 
                skipped_fuzz = True
                print(f"skipped_fuzz 2: {kb_inp.uuid}") 
                continue

            # We are fuzzing
            job = jobs["fuzzer"]
            new_inp_index = len(queue)

            # Grab all the bitmaps so far
            final_bitmap = bytearray([0 for i in range(0, cfg.manager.MAP_SIZE)])
            changed = False
            for file_name in os.listdir(counts_dir): 
                if not file_name.startswith("bitmap_"): 
                    continue
                with open(f"{counts_dir}/{file_name}", 'rb') as bitmap_file:
                    file_content = bytearray(bitmap_file.read())
                    final_bitmap = bytearray([final_bitmap[i] | file_content[i] for i in range(0, len(file_content))])
                    changed = True

            final_bitmap_file = f"{counts_dir}/final_bitmap"
            if changed:
                bitmap_file = open(final_bitmap_file, 'wb') 
                for byte in final_bitmap:
                    bitmap_file.write(bytearray([byte]))
                bitmap_file.close()

            for file_name in os.listdir(counts_dir): 
                if file_name.startswith("bitmap_"): 
                    os.remove(f"{counts_dir}/{file_name}") 

            # Only deterministic fuzz under certain conditions
            if (not kb_inp.additional_information["passed_det"] == "True" and \
                    perf_score >= (kb_inp.depth * 30 \
                    if kb_inp.depth * 30 <= HAVOC_MAX_MULT * 100 else HAVOC_MAX_MULT * 100)):
                        deterministic_fuzz(cfg, kb_inp, job, final_bitmap_file) 
                        kb_inp.additional_information["passed_det"] = "True"

            # Run havoc fuzzer with this input, stage_max times (-n arg) 
                # Run havoc fuzzing
            stage_max = HAVOC_CYCLES * perf_score / havoc_div / 100
            print("Stage_max: %d" % stage_max)
            job.update_count_by(1)
            args = [f"fuzzer.input_file={kb_inp.filepath}", f"fuzzer.ooze.name=afl_havoc.so", \
                    f"fuzzer.analysis_load_file={final_bitmap_file}", \
                    f"fuzzer.job_number={job.get_count()}", \
                    f"fuzzer.iteration_count={stage_max}", \
                    f"fuzzer.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536'"]
            #print(args)
            create_job(cfg, "%s:%s" % (job.name, namespace), job.name, 
                    job.get_count(), args, namespace)  
            total_execs += stage_max
            jobs_created += 1
            print ("uuid for input is %s" % (str(kb_inp.uuid)))

            if kb_inp.uuid in favored and kb_inp.fuzz_level == 0: 
                print("decreasing pending_favored")
                pending_favored -= 1 
            
            fuzz_level = kb_inp.fuzz_level + 1
            kb_inp.fuzz_level = fuzz_level
            kbs.AddInput(kb_inp)

        # Process results
        print("Ran {} jobs this round".format(jobs_created))
        start_time = time.time()
        save_data_file()
        end_time = time.time()
        print(f"Took {end_time-start_time} to save data to files.")
        print(f"Total Exces (underestimated):  {int(total_execs)}")

if __name__=="__main__":
    run()
