#import drcov
import logging
import grpc
import hydra
import os
from os.path import basename
import os.path
import sys
from collections import Counter
spitfire_dir= os.environ.get('SPITFIRE') #"/spitfire" # Env variable
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None)) 
import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg
import google.protobuf.json_format
import subprocess
import shutil
from panda import Panda, blocking
from panda import * 

# Get the environment
input_dir = os.environ.get("INPUTS_DIR")
target_dir = os.environ.get("TARGET_DIR") 
corpus_dir = os.environ.get("CORPUS_DIR")
replay_dir = os.environ.get("REPLAY_DIR")

# Class to contain result of libraries 
class Module: 
    def __init__(self, mod): 
        self.name = mod.name
        self.base = mod.base_addr 
        self.end = mod.base_addr + mod.size
        self.filepath = mod.file

class Address: 
    def __init__(self, module, offset):
        self.module = module
        self.offset = offset

class Edge:
    def __init__(self, addresses, hit_count): 
        self.addresses = addresses
        self.hit_count = hit_count 

def create_and_run_recording(cfg, inputfile, plog_filename): 
    
    #log.info("Creating recording")

    # Copy directory needed to insert into panda recording
    # We need the inputfile and we need the target binary install directory
    copydir = "./copydir"
    if os.path.exists(copydir):
        shutfil.rmtree(copydir)
    os.makedirs(copydir) 
    shutil.copy(inputfile, copydir)
    shutil.copytree(target_dir, copydir + "/install") 

    # Get the qcow file 
    qcow = cfg.taint.qcow;
    qcowfile = basename(qcow)
    qcf = "/qcows/%s" % qcowfile 
    assert(os.path.isfile(qcf))

    # Create panda recording
    replayname = "%s/%s" % (replay_dir, basename(inputfile) + "-panda") 
    print("replay name = [%s]" % replayname)

    # This needs to be changed
    cmd = "cd copydir/install/ && ./%s ~/copydir/%s" % (cfg.target.name, basename(inputfile))
    print(cmd) 
    #cmd = "cd copydir/install/libxml2/.libs && ./xmllint ~/copydir/"+basename(inputfile)
    #print(cmd) 
    #return
    panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", 
            qcow=qcf, mem="1G", extra_args="-display none -nographic -panda general:n=3") 

    @blocking
    def take_recording():
        panda.record_cmd(cmd, copydir, recording_name=replayname)
        panda.stop_run()


    panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
    panda.queue_async(take_recording)
    panda.run()

    # Now insert the plugins and run the replay
    panda.set_pandalog(plog_filename)
    panda.load_plugin("asidstory") 
    panda.load_plugin("edge_coverage")
    panda.load_plugin("loaded_libs")
    panda.run_replay(replayname) 


def analyze_asid(log_entry, program, asids, instr_intervals, first_instr, last_instr): 
    ai = log_entry.asid_info
    if ai.name == program:
        asids.add(ai.asid)
        instr_interval = [ai.start_instr, ai.end_instr]
        instr_intervals.append(instr_interval)
        if first_instr is None:
            first_instr = ai.start_instr
        last_instr = ai.end_instr

    return [first_instr, last_instr]



def ingest_log(cfg, plog_file_name):
    plog_file = "%s/%s" % (os.getcwd(), plog_file_name)
    asids = set([]) 
    instr_intervals = []
    first_instr_for_program = None
    last_instr_for_program = None
    program = cfg.target.name 

    print("Ingesting pandalog") 
    with plog.PLogReader(plog_file) as plr:
        try:
            for i, log_entry in enumerate(plr):
                if log_entry.HasField("asid_info"): 
                    [first_instr_for_program, last_instr_for_program] = \
                    analyze_asid(log_entry, program, asids, instr_intervals, 
                            first_instr_for_program, last_instr_for_program)
        except Exception as e:
            print (str(e))

    edges = [] 
    modules = {} 
    with plog.PLogReader(plog_file) as plr: 
        try: 
            for i, log_entry in enumerate(plr): 
                if not log_entry.asid in asids: 
                    continue 
                if log_entry.HasField("edge_coverage"):
                    for edge in log_entry.edge_coverage.edges: 
                        edges.append(edge)
                if log_entry.HasField("asid_libraries"): 
                    for m in log_entry.asid_libraries.modules:
                        mod = Module(m)
                        if (mod.name == "[???]"):
                            continue 
                        if not (mod.name in modules): 
                            modules[mod.name] = mod
                        else: 
                            if mod.base < modules[mod.name].base:
                                modules[mod.name].base = mod.base
                            if mod.end > modules[mod.name].end:
                                modules[mod.name].end = mod.end 
                       
        except Exception as e:
            print (str(e))
    
    resolved_edges = []
    #i = 0
    for edge in edges:
        #if i == 10:
        #    return
        addresses = []
        #print("Edge %d:" % i)
        for pc in edge.pc:
            #print("PC: %d" % pc) 
            for key in modules:
                #print("Range for module %s is [%d, %d]" % (key, modules[key].base, modules[key].end))
                if pc in range(modules[key].base, modules[key].end):
                    #print("in Module: %s", key) 
                    module = modules[key]
                    offset = pc - modules[key].base
                    #print("at Offset: %d", offset)
                    addresses.append(Address(module, offset))
                    break
        resolved_edges.append(Edge(addresses, edge.hit_count))
        #i+= 1

    return [resolved_edges, modules]


def send_to_database(edges, input_file, modules, channel): 
    kbs = kbpg.KnowledgeBaseStub(channel) 

    kbp_modules = []
    for key in modules: 
        module = modules[key]
        kbp_modules.append(kbp.Module(name=module.name, base=module.base, end=module.end, filepath=module.filepath)) 
    for r in kbs.AddModules(iter(kbp_modules)):
        pass
    #print(result) 

    kb_input = kbp.Input(filepath=input_file)
    input_msg = kbs.AddInput(kb_input)
    kb_edges = []
    for edge in edges:
        addresses = []
        for address in edge.addresses:
            module = address.module
            module = kbp.Module(name=module.name, base=module.base, end=module.end, filepath=module.filepath)
            addresses.append(kbp.Address(module=module, offset=address.offset)) 
        edge_coverage = kbp.EdgeCoverage(hit_count=edge.hit_count, address=addresses, input=kb_input)
        kb_edges.append(edge_coverage) 
        #print(edge_coverage)
        #i+=1
    print(len(kb_edges))
    for r in kbs.AddEdgeCoverage(iter(kb_edges)): 
        pass

    #result = kbs.AddEdgeCoverage(iter(kb_edges))
    #for r in result:
    #    print(r)
    #print(result)


@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):    
    
    input_file = cfg.coverage.input_file 
    plog_file_name = cfg.coverage.plog_file_name
    create_and_run_recording(cfg, input_file, plog_file_name) 

    [edges, modules] = ingest_log(cfg, plog_file_name) 
    #print(edges)
    #return

    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        print("here: connected");
        send_to_database(edges, input_file, modules, channel) 

            
if __name__ == '__main__':
    logging.basicConfig()
    run()
