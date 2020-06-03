
import random

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

# if an edge is in this or fewer inputs,
# consider it rare
# YES: this should be in a config file
RARE_EDGE_INPUT_COUNT = 5

# determine best input to fuzz
# using coverage
def rank_inputs(kbs):

    F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
    C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}

    print ("%d inputs have been fuzzed" % (len(F)))
    print ("%d inputs have coverage info" % (len(C)))
    
    # iterate over set of edges observed for any input for which we have
    # measured coverage 
    # count number of edges with 1, 2, etc inputs
    num_edges = 0
    num_rare_edges = 0
    score = {}

    hist = {}
    for edge in kbs.GetEdges(kbp.Empty()):
        num_edges += 1
        n_msg = kbs.GetNumInputsForEdge(edge)
        n = n_msg.val
        if not (n in hist): hist[n] = 0
        hist[n] += 1
        if n > RARE_EDGE_INPUT_COUNT:
            continue
        # this is a rare edge
        for inp in kbs.GetInputsForEdge(edge):
            # ignore inp if its in F (already fuzzed)
            if inp.uuid in F:
                continue
            num_rare_edges += 1
            if not inp.uuid in score:
                score[inp.uuid] = 0
            score[inp.uuid] += 1
    print ("of %d edges, %d are rare (%d or fewer inputs)" % (num_edges, num_rare_edges, RARE_EDGE_COUNT))
    n_vals = hist.keys()
    n_vals.sort()
    for n in n_vals:
        print ("input_count=%d -- %d edges" % (n, hist[n]))
    # score[inp.uuid] now contains the number of rare edges for that input
    input_score = [(kbs.GetInputById(kbp.id(uuid=iuuid)),score[iuuid]) for iuuid in score.keys()]
    input_score.sort(key=lambda x : x[1], reverse=True)
    return input_score
                   
