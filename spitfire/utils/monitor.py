

# Expect this to run from HOST
# i.e. not from a kubernetes thingy
import numpy as np
import os
import sys
import grpc
import hydra
import logging
import matplotlib
import matplotlib.pyplot as plt
from pprint import pprint
from kubernetes import client, utils, config

spitfire_dir = os.environ.get("SPITFIRE")
spitfire_dir = "/home/hpreslier/raf/spitfire"
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(os.path.realpath(os.path.join(spitfire_dir, "..")))
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None))

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

from spitfire.utils import coverage

def update_map(coord, event, cumulative, base_time): 
    time = event.timestamp.seconds - base_time
    if not coord: 
        base_time = time
        time, cumulative = 0, 0
    if not time in coord:
        coord[time] = 1 + cumulative
    else:
        coord[time] += 1 
        cumulative += 1
    return [cumulative, base_time] 

def display_map(coord, axs, label): 
    x = list(coord.keys())
    y = list(coord.values())
    axs.plot(x, y, 'bo', x, y, 'k') 
    axs.set_xlabel("Time (seconds)")
    axs.set_ylabel("Number of %s" % label) 

@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):

    # Setup access to cluster 
    config.load_kube_config()
    api_instance = client.CoreV1Api() # client.BatchV1Api()

    # peek at pods to see what's running / completed / etc
#    resp = api_instance.list_pod_for_all_namespaces()
#    count = {}
#    for i in resp.items:
#        pt = i.spec.containers[0].image
#        if not (("k8s" in pt) or ("gcr.io" in pt) or ("knowledge" in pt) or ("init" in pt)):
#            s = i.status.phase
#            if not (s in count):
#                count[s] = {}
#            if not (pt in count[s]):
#                count[s][pt] = 0
#            count[s][pt] += 1
#    print("\nPods\n")
#    for s in count.keys():
#        print ("Status=%s:" % s)
#        for pt in count[s].keys():
#            print("  %d %s" % (count[s][pt], pt))
#        print("\n")
    
    
    
    # Connect to the knowledge base 
    with grpc.insecure_channel("172.17.0.5:61111") as channel:
#    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        S = {inp.uuid for inp in kbs.GetSeedInputs(kbp.Empty())} 
        F = {inp.uuid for inp in kbs.GetExecutionInputs(kbp.Empty())}
        C = {inp.uuid for inp in kbs.GetInputsWithCoverage(kbp.Empty())}
        ICV = {inp.uuid for inp in kbs.GetInputsWithoutCoverage(kbp.Empty())}
        T = {inp.uuid for inp in kbs.GetTaintInputs(kbp.Empty())}

        #print("%d seeds" % len(S))
        print("%d fuzzed" % len(F))
        print("%d seedsfuzzed" % (len(S & F)))
        print("%d coverage" % (len(C)))
        print("%d seedscoverage" % (len(S & C)))
        print("%d taint" % len(T))
        
        '''
        cl = coverage.rank_inputs(kbs)
        for p in cl:
            (inp, score) = p
            print ("score=%d inp=%s" % (score, inp.filepath))
        '''

        # Display Edges vs Time
        edge_coord = {} 
        num, bt = 0, 0
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(new_edge_event=True)):
            [num, bt] = update_map(edge_coord, event, num, bt)
        
        # Display Tainted Instrs vs Time
        ti_coord = {}
        num, bt = 0, 0
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(
            new_tainted_instruction_event=True)):
            [num, bt] = update_map(ti_coord, event, num, bt)
        
        # Display all Timing Events  
        intervals = {} # key is analysis + input bytes; value is (start, end) 
        colors = [] 
        color = ['C{}'.format(i) for i in range(3)] 
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(timing_event=True)):
            key = str(event.analysis) + str(event.input)
            time = event.timestamp.seconds
            te_type = event.timing_event.type
            te_event = event.timing_event.event 
            if not key in intervals:
                intervals[key] = [0,0]
                colors.append(color[te_type])
            if te_event == 0: # BEGIN
                intervals[key][0] = time
            elif te_event == 1: # END
                intervals[key][1] = time
        
        begin = [i[0] for i in intervals.values()] 
        end = [i[1] for i in intervals.values()]
        length = list(np.array(end) - np.array(begin)) 
        
        # positions are meaningless? give each a y position (0, 24)
        positions = [[i] for i in np.arange(len(begin))] 
        # line offsets are the x values 
        # line lengths represnts durations 
        #print(begin)
        #print(length)
        #print(colors) 
        #print(positions)
        #print(len(begin))
        #print(len(length))
        #print(len(colors))
        fig, axs = plt.subplots(2, 2)
        axs[0, 0].eventplot(positions=positions, linelengths=length, lineoffsets=begin) 
        axs[0, 0].set_xlabel("Event number") 
        axs[0, 0].set_ylabel("Time (seconds)") 
        
        # Dot plot with x axis as time; y axis as number; color as type 
        coords = []
        fme_total_types = 5
        #color = [i**2 for i in range(5)] 
        color = ['C{}'.format(i) for i in range(fme_total_types)] 
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(fuzzing_manager_event=True)):
            time = event.timestamp.seconds
            fme_type = event.fuzzing_manager_event.type
            number = event.fuzzing_manager_event.number
            #if not time in times: 
            #    times[time] = [] #[0, 0] # [color, number] 
            coords.append([time, color[fme_type], number + 1])
        
        # x should be time, y should be number, type should be color
        print(coords)
        times = [i[0] for i in coords]
        colors = [i[1] for i in coords]
        numbers = [i[2] for i in coords]
        
        plots = []
        for c in color: 
            time_x = [times[i] for i in range(0, len(colors)) if colors[i] == c]
            number_y = [numbers[i] for i in range(0, len(colors)) if colors[i] == c]
            scatter = axs[1,0].scatter(time_x, number_y, color=c)
            plots.append(scatter) 

        axs[1,0].legend((plots[0], plots[1], plots[2], plots[3], plots[4]), \
                    ('SeedFuzz', 'CoverageFuzz', 'TaintFuzz', 'Taint', 'Coverage'), \
           scatterpoints=1, loc='lower right', ncol=2, fontsize=8)
        axs[1,0].set_xlabel("Time (seconds)") 
        axs[1,0].set_ylabel("Round number") 
        
        #legend = axs[1,0].legend(*scatter.legend_elements(),
        #                            loc="lower right", title="Events")
        #axs[1,0].add_artist(legend)
        
        display_map(edge_coord, axs[1,1], "edges")
        display_map(ti_coord, axs[0,1], "tis")
        plt.show()
    return




if __name__ == "__main__":
    logging.basicConfig()
    run()
