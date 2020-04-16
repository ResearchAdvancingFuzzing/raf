#
# Tubby: A taint and coverage based fuzzing manager. 

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
P_SEED_MUTATIONAL_FUZZ = 0.25
P_COVERAGE_FUZZ = 0.25
P_TAINT_FUZZ = 0.25
P_TAINT_ANALYSIS = 0.25
MAX_TAINT_OUT_DEGREE = 16
# this is our compute budget? 
# so, like 10 cores or nodes or whatever
budget = 10 


# Get env
corpus_dir = os.environ.get("CORPUS_DIR")

def create_job_from_yaml(api_instance, num, arg, template_file): 
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
    api_response = api_instance.create_namespaced_job(body=job, namespace="default")
    print("Job created. status='%s'" % str(api_response.status))
    return job

class Job: 
    def __init__(self, name): 
        self.file_name = f"/config_{name}.yaml"
        self.count = 0 

    def update_count_by(self, num): 
        self.count += num

# somehow Heather runs this fn in a kubernetes cron job every M minutes
# M=5 ?
# this cfg is the hydra thing, I hope

@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
#@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml"
def run(cfg):
    job_names = ["taint", "coverage", "fuzzer"]
    jobs = {name:Job(name) for name in job_names}  
    
    #N = consult kubernetes to figure out how much many cores we are using currently
    config.load_incluster_config()
    batch_v1 = client.BatchV1Api() 
    #create_job_from_yaml(batch_v1, 1, "python3.6 run.py", "/config_coverage.yaml")  
    
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        target_msg = kbp.Target(name=cfg.target.name, source_hash=cfg.target.source_hash)
        target_kb = kbs.AddTarget(target_msg) 
        
        fuzz_inputs = []
        uuid = []
        for dirpath,_,filenames in os.walk(corpus_dir): 
            for f in filenames:
                input_msg = kbp.Input(filepath=os.path.join(dirpath, f), seed=True)
                fuzz_input = kbs.AddInput(input_msg)
                fuzz_inputs.append(fuzz_input)
                uuid.append(fuzz_input.uuid)
        uuid = b"".join(uuid)

        corpus_msg = kbp.Corpus(uuid=uuid, input=fuzz_inputs)
        corpus = kbs.AddCorpus(corpus_msg)
        # experiment also needs a seed and a hash of the fuzzing manager 
        experiment_msg = kbp.Experiment(target=target_kb, seed_corpus=corpus)
        experiment = kbs.AddExperiment(experiment_msg) 
        
    
#if N >= budget:
        # we are using all the compute we have -- wait
    #    exit()
        
        #S = consult knowledge base to get set of original corpus seed inputs
        print("Seed")
        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
        for s in S: 
            print(s)
        print("Execution")
        #F = consult knowledge base to get set of inputs we have done mutational fuzzing on so far
        F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
        for f in F:
            print(f)
        print("Inputs With Coverage")
        #C = consult knowledge base to get set of inputs for which we have measured coverage
        C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}
        for c in C:
            print(c)
        print("Inputs without Coverage")
        #ICV = consult knowledge base to get set of interesting inputs that got marginal covg (increased covg)
        ICV = {inp.uuid for inp in kbs.GetInputsWithoutCoverage(kbp.Empty())}
        for icv in ICV:
            print(icv)
        print("Taint Inputs")
        #T = consult knowledge base to get set of inputs for which we have done taint analysis
        T = {inp.uuid for inp in kbs.GetTaintInputs(kbp.Empty())}
        for t in T:
            print(t)

        while True:
            p = random.uniform(0, 1) # generate a random number between 0 and 1 to see what we are doing 

            if False: #True: #p < P_SEED_MUTATIONAL_FUZZ:

                # We want to just fuzz a seed (mutational)

                # set of seed inputs we have not yet fuzzed
                RS = S - F
                if len(RS) == 0:
                    # seed fuzzing not possible -- try something else 
                    continue

                # fuzz one of the remaining seeds chosen at random 
                s = random.choice(list(RS))
                kb_inp = kbs.GetInputById(kbp.id(uuid=s)) 
                print(kb_inp)
                
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                
                args = [f"gtfo.input_file={kb_inp.filepath}"]
                create_job_from_yaml(batch_v1, job.count, args, job.file_name)  

                # cron job finished
                return
                exit()

            elif False: #True: #p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ):

                # We want to do covg-based fuzzing

                # set of inputs for which we have coverage info but have not yet fuzzed
                RC = C - F
                if len(RC) == 0:
                    # covg based fuzzing not possible -- try something else 
                    continue
                
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
                create_job_from_yaml(batch_v1, job.count, args, job.file_name) 
                
                # Choose to fuzz next the input that exposes the most new coverage
                # wrt all other inputs for which we have measured coverage.
                # How do we compute this, exactly?                
                # NB: Better would be to choose with probability, where input that 
                # exposes the most new coverage is most likely and the input that 
                # exposes the least new coverage is least likely.
                

                # Get all 
                # Get edge coverage for an input 
                #c = choose_input_according_to_marginal_coverage(RC)
                #gtfo(c, timeout=cfg.mutfuzz.timeout)
                #tell knowledge base to add s to F?  Or maybe gtfo does that
                # cron job finished 
                exit()

            elif True: # p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ + P_TAINT_FUZZ):

                # We want to do taint-based fuzzing

                # inputs for which we have taint info AND haven't yet fuzzed
                RT = T - F
                if len(RT) == 0:
                    # taint based fuzzing not possible -- try something else
                    continue

                # Choose an input for which we have taint info 
                # At random?  Hmm that's probably not ideal but fine for now.
                t = random.choice(list(RT))
                kb_inp = kbs.GetInputById(kbp.id(uuid=t))
                print(kb_inp)
                #return
                # Now we need to make some actual reccomendations to fuzzer
                # in order that it can make use of taint info.
                
                #fbss = Consult knowledge base taint info to get Fbs for t that taint fewer than MAX_TAINT_OUT_DEGREE instructions
                fbs_to_fuzz = []
                for fbs in kbs.GetFuzzableByteSetsForTaintInput(kb_inp): 
                    #print(fbs.uuid)
                    tm_sum = sum(1 for tm in kbs.GetTaintMappingsForFuzzableByteSet(fbs))
                    #print(tm_sum)
                    if tm_sum < MAX_TAINT_OUT_DEGREE:
                        fbs_to_fuzz.append(fbs)
                # so now, fbs_to_fuzz contains a number of Fuzzable byte sets to fuzz 
                # that are maybe promising 
                # NB: We need a new version of GTFO that can be informed by this, i.e., that 
                # can take as input a set of fuzzable byte sets to fuzz in a focused way 
                #gtfo_taint(t, fbs_to_fuzz, timeout=cfg.mutfuzz.timeout)
                fbs = fbs_to_fuzz[10] 
                fbs_len = len(fbs.label)
                str_fbs = [str(f) for f in fbs.label]
                str_fbs = ','.join(str_fbs)
                # Write fbs to a file 
                job = jobs["fuzzer"]
                job.update_count_by(1) 
                args = [f"gtfo.input_file={kb_inp.filepath}", f"gtfo.ooze.name=restrict_bytes.so", \
                        f"gtfo.extra_args='JIG_MAP_SIZE=65536 ANALYSIS_SIZE=65536 \
                        OOZE_LABELS={str_fbs} OOZE_LABELS_SIZE={fbs_len} OOZE_MODULE_NAME=afl_havoc.so'"] 
                print(args)
                create_job_from_yaml(batch_v1, job.count, args, job.file_name) 
                #tell knowledge base to add s to F?  Or maybe gtfo does that
                # cron job finished 
                exit()

            else:

                # We want to measure taint for some input

                # this is the set of seed inputs unioned with set of interesting inputs 
                # that increase coverage
                # minus those for which we have measured taint already
                IS = S | ICV - T
                # choose one at random to measure taint on? 
                # gotta be a better way maybe using covg?
                t = random.choice(list(IS))
                kb_inp = kbs.GetInputById(kbp.id(uuid=t)) 
                print(kb_inp)
                
                job = jobs["taint"]
                job.update_count_by(1) 
                
                args = [f"gtfo.input_file={kb_inp.filepath}"]
                print(args)
                create_job_from_yaml(batch_v1, job.count, args, job.file_name)  

                #panda_taint(t)
                #tell knowledge base to add t to T?  Or maybe panda taint does that
                # cron job finished
                return
                exit()

                
        
if __name__ == "__main__":
    logging.basicConfig()
    run()
