import sys
from kubernetes import client, config 
import subprocess
import os
import grpc
import matplotlib
import matplotlib.pyplot as plt

results_file_name="/home/hpreslier/raf/sample_results/results"
trace_file_name="/home/hpreslier/raf/sample_results/trace"
spitfire_dir = os.environ.get("SPITFIRE")
if spitfire_dir is None:
    print("Please set the ENV variable SPITFIRE with the path to the directory.") 
    exit()
sys.path.append("/") 
sys.path.append(spitfire_dir) 
sys.path.append(os.path.realpath(os.path.join(spitfire_dir, "...")))
sys.path.append(spitfire_dir + "/protos") 

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg


def main(argv):
    namespace = sys.argv[1]
    f = open(results_file_name, "r")
    top_rated = {int(line.split(':')[0]):line.split(':')[1] for line in f.readlines()}

    f = open(trace_file_name, "r")
    trace_bits_total = {} 
    for line in f.readlines(): 
        tup = line.rstrip().split(':')
        trace_bits_total[tup[0].encode("utf-8")] = [int(x) for x in tup[1].split(',')] 

    print(len(top_rated))
    print(len(trace_bits_total))
    
    # Setup access to cluster 
    config.load_kube_config()
    api_instance = client.CoreV1Api() # client.BatchV1Api()

    # Get the IP of your computer
    process = subprocess.Popen(['curl', 'ifconfig.me'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ip = stdout.decode("utf-8")
    
    # Connect to the knowledge base
    service = api_instance.list_namespaced_service(namespace=namespace)
    port = service.items[0].spec.ports[0].port
    node_port = service.items[0].spec.ports[0].node_port

    print("Connecting to the KB on %s:%s" % (ip, str(node_port)))

    with grpc.insecure_channel('%s:%d' % (ip, node_port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        top_rated = {key:kbs.GetInputById(kbp.id(uuid=val.rstrip("\n").encode("utf-8"))) \
                for key, val in top_rated.items()} 
        trace_bits = [(kbs.GetInputById(kbp.id(uuid=key)), val) \
                for key, val in trace_bits_total.items()]
        trace_bits = sorted(trace_bits_total, key=lambda tup: tup[0].time_found)

        edge_map = {}
        paths_total = 0
        time_list = []
        for (entry, paths) in trace_bits:
            if int(entry.time_found) == 0: # the scale is all off with the seeds 
                continue
            n_paths = 0
            for path in paths:
                if not path in edge_map: 
                    edge_map[path] = 1 
                    n_paths += 1
            paths_total += n_paths
            time_list.append((entry.time_found, paths_total))

        # Coverage map
        x = [time for (time, paths_total) in time_list]
        y = [paths_total for (time, paths_total) in time_list]

        plt.plot(x, y, 'ro')
        plt.xlabel("Time (seconds)")
        plt.ylabel("Number of edges")
        plt.show()


        # Crash map?


if __name__=="__main__":
    if len(sys.argv) != 2:
        print("Usage: python3.6 process.py <namespace>")
        exit()
    main(sys.argv)
