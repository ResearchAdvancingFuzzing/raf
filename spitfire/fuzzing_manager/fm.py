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
spitfire_dir = os.environ.get("SPITFIRE")
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))
import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

# some guess at how much time we'll spend on each of these
P_SEED_MUTATIONAL_FUZZ = 0.2
P_COVERAGE_FUZZ = 0.2
P_TAINT_FUZZ = 0.2
P_TAINT_ANALYSIS = 0.2
P_COVERAGE = 0.2
MAX_TAINT_OUT_DEGREE = 16

# Compute budget 
# so, like 10 cores or nodes or whatever
budget = 10 


# Get env
corpus_dir = os.environ.get("CORPUS_DIR")

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
    return job

class Job: 
    def __init__(self, name): 
        self.file_name = f"/config_{name}.yaml"
        self.count_file = "/%s" % name
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
    
    # Cleanup anything from before 
    for cj in batch_v1.list_namespaced_job(namespace=namespace, label_selector='tier=backend').items: 
        if not cj.status.active and cj.status.succeeded: 
            batch_v1.delete_namespaced_job(name=cj.metadata.name, namespace=namespace, propagation_policy="Background") 
    
    # Connect to the knowledge base 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)
        
        #if N >= budget:
        # we are using all the compute we have -- wait
        #    exit()
       
        while True:
                
            # Get all sets of inputs 

            #S = set of original corpus seed inputs
            print("Seed")
            S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
            for s in S: 
                print(s)
            
            #F = set of inputs we have done mutational fuzzing on so far
            print("Execution")
            F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
            for f in F:
                print(f)
            
            #C = set of inputs for which we have measured coverage
            print("Inputs With Coverage")
            C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}
            for c in C:
                print(c)
            
            #ICV = set of interesting inputs that got marginal covg (increased covg)
            print("Inputs without Coverage")
            ICV = {inp.uuid for inp in kbs.GetInputsWithoutCoverage(kbp.Empty())}
            for icv in ICV:
                print(icv)
            
            #T = set of inputs for which we have done taint analysis
            print("Taint Inputs")
            T = {inp.uuid for inp in kbs.GetTaintInputs(kbp.Empty())}
            for t in T:
                print(t) 

            # Generate a random number between 0 and 1 to see what we are doing 
            p = random.uniform(0, 1) 

            if p < P_SEED_MUTATIONAL_FUZZ:

                # We want to just fuzz a seed (mutational)

                # Set of seed inputs we have not yet fuzzed
                RS = S - F
                if len(RS) == 0:
                    # seed fuzzing not possible -- try something else 
                    continue

                # Fuzz one of the remaining seeds chosen at random 
                s = random.choice(list(RS))
                kb_inp = kbs.GetInputById(kbp.id(uuid=s)) 
                print(kb_inp)
                
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                
                args = [f"gtfo.input_file={kb_inp.filepath}"]
                create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace)  

                # cron job finished
                return
                exit()

            elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ):

                # We want to do covg-based fuzzing

                # Set of inputs for which we have coverage info but have not yet fuzzed
                RC = C - F
                if len(RC) == 0:
                    # Covg based fuzzing not possible -- try something else 
                    continue
                
                # Choose to fuzz next the input that exposes the most new coverage
                # wrt all other inputs for which we have measured coverage.
                max_inp = None
                max_cov = 0
                for inp_id in RC:
                    inp = kbs.GetInputById(kbp.id(uuid=inp_id))
                    print(inp)
                    n_cov = sum(1 for c in  kbs.GetEdgeCoverageForInput(inp))
                    print(n_cov)
                    if n_cov > max_cov:
                        max_cov = n_cov
                        max_inp = inp
                
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                args = [f"gtfo.input_file={max_inp.filepath}"] 
                create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace) 
                
                # NB: Better would be to choose with probability, where input that 
                # exposes the most new coverage is most likely and the input that 
                # exposes the least new coverage is least likely.
                
                # cron job finished 
                return
                exit()

            elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ + P_TAINT_FUZZ):

                # We want to do taint-based fuzzing

                # Inputs for which we have taint info AND haven't yet fuzzed
                RT = T - F
                if len(RT) == 0:
                    # Taint based fuzzing not possible -- try something else
                    continue

                # Choose an input for which we have taint info 
                # At random, for now (not ideal) 
                t = random.choice(list(RT))
                kb_inp = kbs.GetInputById(kbp.id(uuid=t))
                print(kb_inp)
                # Now we need to make some actual reccomendations to fuzzer
                # in order that it can make use of taint info.
                
                # Consult knowledge base taint info to get Fbs for kb_inp
                # that taint fewer than MAX_TAINT_OUT_DEGREE instructions
                fbs_to_fuzz = []
                for fbs in kbs.GetFuzzableByteSetsForTaintInput(kb_inp): 
                    tm_sum = sum(1 for tm in kbs.GetTaintMappingsForFuzzableByteSet(fbs))
                    if tm_sum < MAX_TAINT_OUT_DEGREE:
                        fbs_to_fuzz.append(fbs)
                
                # so now, fbs_to_fuzz contains a number of Fuzzable byte sets to fuzz 
                # that are maybe promising 
                
                # Choose an fbs at random, for now
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
                create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace) 
                
                # cron job finished 
                exit()

            elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ + P_TAINT_FUZZ + P_TAINT_ANALYSIS):

                # We want to measure taint for some input

                # Seed inputs and interesting inputs that increase coverage
                # minus those for which we have measured taint already
                IS = S | ICV - T
                
                if len(IS) == 0:
                    # Taint analysis not possible -- try something else
                    continue 

                # Choose one at random to measure taint on 
                # (gotta be a better way maybe using covg)
                t = random.choice(list(IS))
                kb_inp = kbs.GetInputById(kbp.id(uuid=t)) 
                print(kb_inp)
                
                job = jobs["taint"]
                job.update_count_by(1) 
                
                args = [f"taint.input_file={kb_inp.filepath}"]
                print(args)
                create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace)  

                # cron job finished
                return
                exit()

            else: 
                # Do some coverage 
                
                # Inputs that need coverage run; so seed inputs if they don't already have coverage
                # or new intersting inputs without coverage 
                IC = S - C | ICV 
                if len(IC) == 0:
                    # Coverage not possible -- try something else
                    continue 

                t = random.choice(list(IC)) 
                kb_inp = kbs.GetInputById(kbp.id(uuid=t)) 
                print(kb_inp)

                job = jobs["coverage"] 
                job.update_count_by(1) 
                
                args = [f"coverage.input_file={kb_inp.filepath}"] 
                print(args)
                create_job_from_yaml(batch_v1, job.get_count(), args, job.file_name, namespace) 

                return
                exit() 


if __name__ == "__main__":
    logging.basicConfig()
    run()
