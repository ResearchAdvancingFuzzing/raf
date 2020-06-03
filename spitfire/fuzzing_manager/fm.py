#
# Tm: A taint and coverage based fuzzing manager. 

#

from kubernetes import client, utils, config
import os
import yaml
import time
import random
import hydra
import logging
import grpc 
import sys
from pprint import pprint

spitfire_dir = os.environ.get("SPITFIRE")
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))
import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

from spitfire.utils import coverage

# some guess at how much time we'll spend on each of these
fuzzing_dist = [("SEED_MUTATIONAL_FUZZ", 0.3), \
                ("COVERAGE_FUZZ", 0.3), \
                ("TAINT_FUZZ", 0.2), \
                ("TAINT_ANALYSIS", 0.2), \
                ("COVERAGE", 0.3)]

MAX_TAINT_OUT_DEGREE = 16

RARE_EDGE_COUNT = 3

# Compute budget 
# so, like 10 cores or nodes or whatever
budget = 10 


# Get env
corpus_dir = os.environ.get("CORPUS_DIR")
counts_dir = os.environ.get("COUNTS_DIR") 



# if you have a distribution such as
# where 0.3 is probability of "a", etc
# this function will choose according to the
# distribution. NB: the distribution needn't
# be normalized before hand.
# dist = [("a", 0.3), ("b", 0.2), ("c", 0.5)]
def choose(dist):
    the_sum = 0
    for item in dist:
        (label, val) = item
        the_sum += val
    x = random.random()
    prob_sum = 0.0
    for item in dist:
        (label, val) = item
        prob_sum += val / the_sum        
        if prob_sum > x:
            return label


def create_job_from_yaml(api_instance, num, arg, template_file, namespace): 
    commands = ["python3.6"]
    args = ["run.py"]
    args.extend(arg)
    print(args) # override hydra here
    #return
    with open( template_file ) as f:
        job=yaml.safe_load(f)
        print(job)
        name ="%s-%s" % (job["metadata"]["name"], str(num)) 
        job["metadata"]["name"] = name
        job["spec"]["template"]["metadata"]["name"] = name
        job["spec"]["template"]["spec"]["containers"][0]["name"] = name
        job["spec"]["template"]["spec"]["containers"][0]["command"] = commands
        job["spec"]["template"]["spec"]["containers"][0]["args"] = args
        #job["spec"]["template"]["metadata"]["labels"]["app"]=name
	#job["spec"]["template"]["spec"]["containers"][0]["image"]=image
	#job["spec"]["template"]["spec"]["containers"][0]["command"]=commands
	#job["spec"]["template"]["spec"]["containers"][0]["env"]=envs
    print(job)
    api_response = api_instance.create_namespaced_job(body=job, namespace=namespace)
    print("Job created. status='%s'" % str(api_response.status))
#    pprint(api_response)
    return job

class Job: 
    def __init__(self, name): 
        self.file_name = f"/config_{name}.yaml"
        self.count_file = "%s/%s" % (counts_dir, name)
        # Setup the count; we need them to be persistent 
        try:
            with open(self.count_file) as f:
                self.count = int(f.read())
        except IOError:
            self.count = 0
        else:
            f.close() 

    def get_count(self): 
        return self.count

    def update_count_by(self, num): 
        with open(self.count_file, "w") as f:
            f.write(str(self.count + num))
        self.count += num
        return self.count 


# count how many pods are in the various phases
# returns number that are running + pending
def take_stock(core_v1):
    resp = core_v1.list_pod_for_all_namespaces()
    count = {}
    for i in resp.items:
        pt = i.spec.containers[0].image
        if not (("k8s" in pt) or ("gcr.io" in pt) or ("knowledge" in pt) or ("init" in pt)):
            s = i.status.phase
            if not (s in count):
                count[s] = {}
            if not (pt in count[s]):
                count[s][pt] = 0
            count[s][pt] += 1
    rp = 0
    for s in count.keys():
        print ("Status=%s:" % s)
        if s=="Running" or s=="Pending":
            rp += 1
        for pt in count[s].keys():
            print("  %d %s" % (count[s][pt], pt))
        print("\n")
    return rp

    
@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):

    # Setup job information
    job_names = ["taint", "coverage", "fuzzer"]
    jobs = {name:Job(name) for name in job_names}  

    #N = consult kubernetes to figure out how much many cores we are using currently
    
    # Setup access to cluster 
    config.load_incluster_config()
    batch_v1 = client.BatchV1Api()
    core_v1 = client.CoreV1Api() 
    namespace = "default"

    # are any fm.py still running?
    # are any pods Pending?
    resp = core_v1.list_pod_for_all_namespaces()
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

    if num_pending > 0:
        print ("Some pods are Pending -- exiting")
    
    # Cleanup anything from before 
    for cj in batch_v1.list_namespaced_job(namespace=namespace, label_selector='tier=backend').items: 
        if not cj.status.active and cj.status.succeeded: 
            batch_v1.delete_namespaced_job(name=cj.metadata.name, namespace=namespace, propagation_policy="Background") 

    # Connect to the knowledge base 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        res = kbs.GetMode(kbp.Empty())
        print ("FM mode is %d" % res.type)

        if res.type == 2:
            print ("PAUSED -- do nothing")
            return
        elif res.type == 1:
            print ("RUN -- fuzzing happens")
        else:
            print ("Impossible mode?")
            assert (1==0)



        # Get all sets of inputs 
        # NB: Moved this outside of loop below, in which we launch potentially
        # several jobs which could alter these sets. That's because we have to
        # update the sets manually since the loop goes too fast for any of the
        # jobs to have started up
        
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
        P = set([])
            
        jobs_created = 0

        the_time = None

        choice_succeeded = True
        
        while True:

            if not (the_time is None) and choice_succeeded:
                print ("Time to complete last round: %f seconds" % (time.time() - the_time))

            the_time = time.time()
                
            if jobs_created >= 5:
                print("Created %d jobs -- exiting" % jobs_created)
                return

            num_running_pods = take_stock(core_v1)
            print ("\n%d running pods" % num_running_pods)
    
            if num_running_pods >= 25:
                print("Exceeded budget -- exiting")
                return

            print("Under budget -- proceeding")

            # Choose according to a distribution what fuzzing action to pursue
            fuzzing_choice = choose(fuzzing_dist)

            print ("fuzzing_choice = %s" % fuzzing_choice)
            
            choice_succeed = False
            
            if fuzzing_choice == "SEED_MUTATIONAL_FUZZ":

                # We want to just fuzz a seed (mutational fuzzing)

                # Set of seed inputs we have not yet fuzzed
                RS = S - F
                # exclude pending
                RS -= P

                if len(RS) == 0:
                    # seed fuzzing not possible -- try something else 
                    continue

                print ("Mutational fuzzing selected")
                                
                # Fuzz one of the remaining seeds chosen at random 
                s_uuid = random.choice(list(RS))
                kb_inp = kbs.GetInputById(kbp.id(uuid=s_uuid)) 
                print(kb_inp)
                
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                
                args = [f"gtfo.input_file={kb_inp.filepath}"]
                try:
                    kbs.MarkInputAsPending(kb_inp)
                    create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace)  
                    print ("uuid for input is %s" % (str(s_uuid)))
                except Exception as e:
                    print("Unable to create job exception = %s" % str(e))
                    # try again
                    continue
                
                jobs_created += 1
                
                choice_succeeded = True
                continue

            elif fuzzing_choice == "COVERAGE_FUZZ":

                # We want to do covg-based fuzzing
                
                # Set of inputs for which we have coverage info but have not yet fuzzed
                RC = C - F
                # exclude pending
                RC -= P

                if len(RC) == 0:
                    # Covg based fuzzing not possible -- try something else 
                    continue

                print ("Coverage-based fuzzing selected")

                # function that raks inputs, using coverage.
                # Intent is that higher ranks inputs should be better choices
                # for fuzzing in some sense (more likely to uncover new code,
                # more likely to cause a crash
                inp_score_list = coverage.rank_inputs(kbs)

                (best_inp, score) = inp_score_list[0]
                
                print("Best input has score of %d" % score)

                max_inp = best_inp
                
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                args = [f"gtfo.input_file={max_inp.filepath}"] 
                try:
                    kbs.MarkInputAsPending(kb_inp)
                    create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace) 
                    print ("uuid for input is %s" % (str(max_inp.uuid)))
                except Exception as e:
                    print("Unable to create job exception = %s" % str(e))
                    # try again
                    continue
                
                jobs_created += 1

                choice_succeeded = True
                continue

            elif fuzzing_choice == "TAINT_FUZZ":

                # We want to do taint-based fuzzing

                # Inputs for which we have taint info AND haven't yet fuzzed
                RT = T - F
                # exclude pending
                RT -= P

                if len(RT) == 0:
                    # Taint based fuzzing not possible -- try something else
                    continue

                print ("Taint-based fuzzing selected")                

                # Choose an input for which we have taint info 
                # At random, for now (not ideal) 
                t = random.choice(list(RT))
                kb_inp = kbs.GetInputById(kbp.id(uuid=t))
                print(kb_inp)
                # Now we need to make some actual reccomendations to fuzzer
                # in order that it can make use of taint info.
                
                # Consult knowledge base taint info to get Fuzzable Byte Sets (Fbs)
                # for kb_inp. These are contiguous byte ranges in the input file that
                # were seen to taint some internal program quantity (like a branch or
                # a pointer for a load or store, etc) for some program instruction.
                # Further, we prefer Fbs that are *selective*, meaning they taint only
                # a small number of instructions: fewer than MAX_TAINT_OUT_DEGREE
                fbs_to_fuzz = []
                for fbs in kbs.GetFuzzableByteSetsForTaintInput(kb_inp): 
                    tm_sum = sum(1 for tm in kbs.GetTaintMappingsForFuzzableByteSet(fbs))
                    if tm_sum < MAX_TAINT_OUT_DEGREE:
                        fbs_to_fuzz.append(fbs)
                
                # so now, fbs_to_fuzz contains a number of Fuzzable byte sets to fuzz 
                # that are maybe promising since they are all somewhat selective
                
                # Choose one of those fbs at random, for now
                fbs = random.choice(fbs_to_fuzz)
                fbs_len = len(fbs.label)
                str_fbs = ','.join([str(f) for f in fbs.label])
                # Run fuzzer with this fbs 
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                args = [f"gtfo.input_file={kb_inp.filepath}", f"gtfo.ooze.name=restrict_bytes.so", \
                        f"gtfo.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536 \
                        OOZE_LABELS={str_fbs} OOZE_LABELS_SIZE={fbs_len} OOZE_MODULE_NAME=afl_havoc.so'"] 
                print(args)
                try:
                    kbs.MarkInputAsPending(kb_inp)
                    create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace) 
                    print ("uuid for input is %s" % (str(kb_inp.uuid)))
                except Exception as e:
                    print("Unable to create job exception = %s" % str(e))
                    # try again
                    continue
                    
                jobs_created += 1

                choice_succeeded = True                
                continue

            elif fuzzing_choice == "TAINT_ANALYSIS":

                # We want to measure taint for some input

                # Seed inputs and interesting inputs that increase coverage
                # minus those for which we have measured taint already
                IS = (S | ICV) - T
                # exclude pending
                IS -= P
                
                if len(IS) == 0:
                    # Taint analysis not possible -- try something else
                    continue 

                print("Taint measure selected")
                                
                # Choose one at random to measure taint on 
                # (gotta be a better way maybe using covg)
                t = random.choice(list(IS))
                kb_inp = kbs.GetInputById(kbp.id(uuid=t)) 
                print(kb_inp)
                
                job = jobs["taint"]
                job.update_count_by(1) 
                
                args = [f"taint.input_file={kb_inp.filepath}"]
                print(args)
                try:
                    kbs.MarkInputAsPending(kb_inp)
                    create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace)  
                    print ("uuid for input is %s" % (str(kb_inp.uuid)))
                except Exception as e:
                    print("Unable to create job exception = %s" % str(e))
                    # try again
                    continue
                    
                jobs_created += 1

                choice_succeeded = True                
                continue

            else: 
                # Do some coverage 

                # Inputs that need coverage run; so seed inputs if they don't already have coverage
                # or new intersting inputs without coverage 
#                IC = S - C | ICV
                IC = (S | ICV) - C
                # exclude pending
                IC -= P
                
                if len(IC) == 0:
                    # Coverage not possible -- try something else
                    continue 

                print ("Coverage measure selected")
                
                t = random.choice(list(IC)) 
                kb_inp = kbs.GetInputById(kbp.id(uuid=t)) 
                print(kb_inp)

                job = jobs["coverage"] 
                job.update_count_by(1) 
                
                args = [f"coverage.input_file={kb_inp.filepath}"] 
                print(args)
                try:
                    kbs.MarkInputAsPending(kb_inp)
                    create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace) 
                    print ("uuid for input is %s" % (str(kb_inp.uuid)))
                except Exception as e:
                    print("Unable to create job exception = %s" % str(e))
                    # try again
                    continue

                jobs_created += 1

                choice_succeeded = True                
                continue



if __name__ == "__main__":
    logging.basicConfig()
    run()
