

# Expect this to run from HOST
# i.e. not from a kubernetes thingy
import numpy as np
import subprocess
import os
import sys
import grpc
import hydra
import logging
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from pprint import pprint
from kubernetes import client, utils, config

spitfire_dir = os.environ.get("SPITFIRE")
if spitfire_dir is None:
    print("Please set the ENV variable SPITFIRE with the path to the directory.")
    exit()
sys.path.append("/")
sys.path.append(spitfire_dir)
sys.path.append(os.path.realpath(os.path.join(spitfire_dir, "..")))
sys.path.append(spitfire_dir + "/protos")


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

@hydra.main(config_path=f"{spitfire_dir}/config/config.yaml")
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
    
    
    # Get the IP of your computer
    process = subprocess.Popen(['curl', 'ifconfig.me'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ip = stdout.decode("utf-8") 
    
    # Connect to the knowledge base
    namespace = cfg.campaign.id
    service = api_instance.list_namespaced_service(namespace=namespace)
    port = service.items[0].spec.ports[0].port
    node_port = service.items[0].spec.ports[0].node_port

    print("Connecting to the KB on %s:%s" % (ip, str(node_port))

    with grpc.insecure_channel('%s:%d' % (ip, node_port)) as channel:
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

        fig, axs = plt.subplots(2, 2)
        
        # Display Edges vs Time
        edge_coord = {} 
        num, bt = 0, 0
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(new_edge_event=True)):
            [num, bt] = update_map(edge_coord, event, num, bt)
        display_map(edge_coord, axs[1,1], "edges")
        
        # Display Tainted Instrs vs Time
        ti_coord = {}
        num, bt = 0, 0
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(
            new_tainted_instruction_event=True)):
            [num, bt] = update_map(ti_coord, event, num, bt)
        display_map(ti_coord, axs[0,1], "tis")
        
        # Display all Timing Events 
        total_te_types = 3
        color_chart = ['C{}'.format(i) for i in range(total_te_types)] 
        intervals = {} # key is analysis + input bytes; value is (start, end) 
        colors = [] 
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(timing_event=True)):
            key = str(event.analysis) + str(event.input)
            time = event.timestamp.seconds
            te_type = event.timing_event.type
            te_event = event.timing_event.event 
            if not key in intervals:
                intervals[key] = [0,0]
                colors.append(color_chart[te_type])
            if te_event == 0: # BEGIN
                intervals[key][0] = time
            elif te_event == 1: # END
                intervals[key][1] = time
        
        begin = [i[0] for i in intervals.values()] 
        end = [i[1] for i in intervals.values()]
        length = list(np.array(end) - np.array(begin)) 
        
        # positions are meaningless? give each a discrete y position
        # line offsets are the x values 
        # line lengths represnts durations 
        positions = [[i] for i in np.arange(len(begin))] 
        axs[1, 0].eventplot(positions=positions, linelengths=length, lineoffsets=begin) 
        axs[1, 0].set_xlabel("Event number") 
        axs[1, 0].set_ylabel("Time (seconds)") 
        
        # Display all Fuzzing Manager Events 
        coords = []
        fme_total_types = 5
        color_chart = ['C{}'.format(i) for i in range(fme_total_types)] 
        for event in kbs.GetFuzzingEvents(kbp.FuzzingEventFilter(fuzzing_manager_event=True)):
            time = event.timestamp.seconds
            fme_type = event.fuzzing_manager_event.type
            number = event.fuzzing_manager_event.number
            coords.append([time, color_chart[fme_type], number + 1])
        
        times = [i[0] for i in coords]
        positions = [[i] for i in times] # Treat each one individually
        colors = [i[1] for i in coords]
        numbers = [i[2] for i in coords] 

        # Create the event plot for FuzzingManagerEvents 
        labels = ["SeedFuzz", "CoverageFuzz", "TaintFuzz", "Taint", "Coverage"]
        axs[0,0].eventplot(positions, colors=colors, lineoffsets=numbers, 
                linelengths=0.5, label=labels)
        custom_lines = [Line2D([0], [0], color=c, lw=2) for c in color_chart]
        axs[0,0].legend(custom_lines, labels, bbox_to_anchor=(0., 1.0, 1., .10), 
                loc=3,ncol=3, mode="expand", borderaxespad=0.)
        axs[0,0].set_xlabel("Time (seconds)") 
        axs[0,0].set_ylabel("Round number") 

        plt.show() 

        # Display number of inputs increasing coverage over time 
        fig, axs = plt.subplots(1,1)
        coord = {} 
        num, bt = 0, 0
        for event in kbs.GetFuzzingEvents(
                kbp.FuzzingEventFilter(increased_coverage_event=True)):
            [num, bt] = update_map(coord, event, num, bt)
        display_map(coord, axs, "inputs increasing coverage")
        
        plt.show()
    return




if __name__ == "__main__":
    logging.basicConfig()
    run()
