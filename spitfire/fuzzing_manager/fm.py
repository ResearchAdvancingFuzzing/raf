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

# this is our compute budget? 
# so, like 10 cores or nodes or whatever
budget = 10 


# Get env
corpus_dir = os.environ.get("CORPUS_DIR")

def create_job_from_yaml(api_instance, num, commands, args, template_file): 
    commands = ["pwd"] # list
    args = [""] # override hydra here

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
        self.file_name = f"config_{name}.yaml"
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
        
        for s in kbs.GetSeedInputs(kbp.Empty()): 
            print(s)
        return
    
#if N >= budget:
        # we are using all the compute we have -- wait
    #    exit()
        S = kbs.GetSeedInputs()  
        F = kbs.GetExecutionInputs()
        C = kbs.GetInputsWithCoverage()
        ICV = kbs.GetInputsWithoutCoverage()
        T = kbs.GetTaintInputs()
        #S = consult knowledge base to get set of original corpus seed inputs
        #F = consult knowledge base to get set of inputs we have done mutational fuzzing on so far
        #C = consult knowledge base to get set of inputs for which we have measured coverage
        #ICV = consult knowledge base to get set of interesting inputs that got marginal covg (increased covg)
        #T = consult knowledge base to get set of inputs for which we have done taint analysis

    while True:
        p = random.uniform(0, 1) # generate a random number between 0 and 1 to see what we are doing 

        if p < P_SEED_MUTATIONAL_FUZZ:

            # We want to just fuzz a seed (mutational)

            # set of seed inputs we have not yet fuzzed
            RS = S - F
            if len(RS) == 0:
                # seed fuzzing not possible -- try something else 
                continue

            # fuzz one of the remaining seeds chosen at random 
            s = random.choice(RS)
            # s is a uuid 
            kb_inp = kbs.GetInputById(s) 
            # Run fuzzer here with ths kb_inp 

            #gtfo(s, timeout=cfg.mutfuzz.timeout)
            #tell knowledge base to add s to F?  Or maybe gtfo does that
            # cron job finished
            exit()

        elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ):

            # We want to do covg-based fuzzing

            # set of inputs for which we have coverage info but have not yet fuzzed
            RC = C - F
            if len(RC) == 0:
                # covg based fuzzing not possible -- try something else 
                continue

            # Choose to fuzz next the input that exposes the most new coverage
            # wrt all other inputs for which we have measured coverage.
            # How do we compute this, exactly?                
            # NB: Better would be to choose with probability, where input that 
            # exposes the most new coverage is most likely and the input that 
            # exposes the least new coverage is least likely.
            c = choose_input_according_to_marginal_coverage(RC)
            gtfo(c, timeout=cfg.mutfuzz.timeout)
            #tell knowledge base to add s to F?  Or maybe gtfo does that
            # cron job finished 
            exit()

        elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ + P_TAINT_FUZZ):

            # We want to do taint-based fuzzing

            # inputs for which we have taint info AND haven't yet fuzzed
            RT = T - F
            if len(RT) == 0:
                # taint based fuzzing not possible -- try something else
                continue

            # Choose an input for which we have taint info 
            # At random?  Hmm that's probably not ideal but fine for now.
            t = random.choice(RT)

            # Now we need to make some actual reccomendations to fuzzer
            # in order that it can make use of taint info.
            
            #fbss = Consult knowledge base taint info to get Fbs for t that taint fewer than MAX_TAINT_OUT_DEGREE instructions
            fbs_to_fuzz = set([])
            for fbs in fbss:
                if len(taint_mappings_for_fbs(fbs)) < MAX_TAINT_IN_DEGREE:
                    fbs_to_fuzz.add(fbs)
            # so now, fbs_to_fuzz contains a number of Fuzzable byte sets to fuzz 
            # that are maybe promising 
            # NB: We need a new version of GTFO that can be informed by this, i.e., that 
            # can take as input a set of fuzzable byte sets to fuzz in a focused way 
            gtfo_taint(t, fbs_to_fuzz, timeout=cfg.mutfuzz.timeout)
            #tell knowledge base to add s to F?  Or maybe gtfo does that
            # cron job finished 
            exit()

        else:

            # We want to measure taint for some input

            # this is the set of seed inputs unioned with set of interesting inputs 
            # that increase coverage
            # minus those for which we have measured taint already
            IS = S + ICV - T

            # choose one at random to measure taint on? 
            # gotta be a better way maybe using covg?
            t = random.random(IS)
            panda_taint(t)
            #tell knowledge base to add t to T?  Or maybe panda taint does that
            # cron job finished
            exit()

                
        
if __name__ == "__main__":
    logging.basicConfig()
    run()
