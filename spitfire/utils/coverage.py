
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

    # iterate over set of edges observed for any input for which we have
    # measured coverage 
    # count number of edges with 1, 2, etc inputs
    hist = {}
    counts_obs = set([])                
    num_edges = 0
    E = {e.uuid for e in kbs.GetEdges(kbp.Empty())}
    print("Total of %d edges for all inputs" % len(E))
    num_inputs_per_edge = {}        
    for euuid in E:
        edge = kbs.GetEdgeById(kbp.id(uuid=euuid))
        num_edges += 1
        # should be number of inputs that cover this edge
        EI = {inp.uuid for inp in kbs.GetInputsForEdge(edge)}
        n = len(EI)
        a0 = edge.address[0]
        a1 = edge.address[1]
        counts_obs.add(n)
        if not (n in hist):
            hist[n] = 0
        hist[n] += 1
        num_inputs_per_edge[str(euuid)] = n

    list_counts_obs = list(counts_obs)
    list_counts_obs.sort()
    for c in list_counts_obs:
        print("%d edges with %d inputs" % (hist[c], c))

    RC = C - F
    print ("%d covg inputs that have not been fuzzed" % (len(RC)))
    input_score = []
    for iuuid in RC:
        inp = kbs.GetInputById(kbp.id(uuid=iuuid))
        nn = {}
        num_edges = 0
        for e in kbs.GetEdgesForInput(inp):
            if (str(e.uuid) in num_inputs_per_edge):
                n = num_inputs_per_edge[str(e.uuid)]
                if not (n in nn): nn[n] = 0
                nn[n] += 1
                num_edges += 1
        print ("input %s num_edges=%d " % (inp.filepath, num_edges))
        num_rare = 0
        for n in range(1,RARE_EDGE_INPUT_COUNT+1):
            if n in nn:
                num_rare += nn[n]
                print("  -- %d edges with %d input " % (nn[n], n))
        print ("  -- %d total rare edges" % num_rare)
        p = (inp, num_rare)
        input_score.append(p)        
    input_score.sort(key=lambda x : x[1], reverse=True)
    return input_score
        
