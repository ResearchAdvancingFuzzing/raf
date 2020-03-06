#
# Tubby: A taint and coverage based fuzzing manager. 
#
#

# some guess at how much time we'll spend on each of these
P_SEED_MUTATIONAL_FUZZ = 0.25
P_COVERAGE_FUZZ = 0.25
P_TAINT_FUZZ = 0.25
P_TAINT_ANALYSIS = 0.25

# this is our compute budget? 
# so, like 10 cores or nodes or whatever
budget = 10 

# somehow Heather runs this fn in a kubernetes cron job every M minutes
# M=5 ?
# this cfg is the hydra thing, I hope
def run(cfg):

    N = consult kubernetes to figure out how much many cores we are using currently

    if N >= budget:
        # we are using all the compute we have -- wait
        exit()

    S = consult knowledge base to get set of original corpus seed inputs
    F = consult knowledge base to get set of inputs we have done mutational fuzzing on so far
    C = consult knowledge base to get set of inputs for which we have measured coverage
    ICV = consult knowledge base to get set of interesting inputs that got marginal covg (increased covg)
    T = consult knowledge base to get set of inputs for which we have done taint analysis

    while True:
        p = random.random()

        if p < P_SEED_MUTATIONAL_FUZZ:

            # We want to just fuzz a seed (mutational)

            # set of seed inputs we have not yet fuzzed
            RS = S - F
            if |RS| == 0:
                # seed fuzzing not possible -- try something else 
                continue

            # fuzz one of the remaining seeds chosen at random 
            s = random.choice(RS)
            gtfo(s, timeout=cfg.mutfuzz.timeout)
            tell knowledge base to add s to F?  Or maybe gtfo does that
            # cron job finished
            exit()

        elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ):

            # We want to do covg-based fuzzing

            # set of inputs for which we have coverage info but have not yet fuzzed
            RC = C - F
            if |RC| == 0:
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
            tell knowledge base to add s to F?  Or maybe gtfo does that
            # cron job finished 
            exit()

        elif p < (P_SEED_MUTATIONAL_FUZZ + P_COVERAGE_FUZZ + P_TAINT_FUZZ):

            # We want to do taint-based fuzzing

            # inputs for which we have taint info AND haven't yet fuzzed
            RT = T - F
            if |RT| == 0:
                # taint based fuzzing not possible -- try something else
                continue

            # Choose an input for which we have taint info 
            # At random?  Hmm that's probably not ideal but fine for now.
            t = random.choice(RT)

            # Now we need to make some actual reccomendations to fuzzer
            # in order that it can make use of taint info.
            fbss = Consult knowledge base taint info to get Fbs for t that taint fewer than MAX_TAINT_OUT_DEGREE instructions
            fbs_to_fuzz = set([])
            for fbs in fbss:
                if len(taint_mappings_for_fbs(fbs)) < MAX_TAINT_IN_DEGREE:
                    fbs_to_fuzz.add(fbs)
            # so now, fbs_to_fuzz contains a number of Fuzzable byte sets to fuzz 
            # that are maybe promising 
            # NB: We need a new version of GTFO that can be informed by this, i.e., that 
            # can take as input a set of fuzzable byte sets to fuzz in a focused way 
            gtfo_taint(t, fbs_to_fuzz, timeout=cfg.mutfuzz.timeout)
            tell knowledge base to add s to F?  Or maybe gtfo does that
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
            tell knowledge base to add t to T?  Or maybe panda taint does that
            # cron job finished
            exit()

        
        
        




