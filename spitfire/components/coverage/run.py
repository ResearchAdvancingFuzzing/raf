#import drcov
from os.path import join,getsize
import subprocess as sp
import logging
import grpc
import hydra
import os
from os.path import basename
import os.path
import sys
from collections import Counter

# Get the environment
namespace = os.environ.get("NAMESPACE")
spitfire_dir = "/%s%s" % (namespace, os.environ.get('SPITFIRE_DIR'))
input_dir = "/%s%s" % (namespace, os.environ.get("INPUTS_DIR"))
target_dir = "/%s%s" % (namespace, os.environ.get("TARGET_DIR"))
corpus_dir = "/%s%s" % (namespace, os.environ.get("CORPUS_DIR"))
replay_dir = "/%s%s" % (namespace, os.environ.get("REPLAY_DIR"))

# Add to the path 
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")

import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg
import google.protobuf.json_format
import subprocess
import shutil
from panda import Panda, blocking
from panda import * 
from google.protobuf import text_format 

log = logging.getLogger(__name__)


# Class to contain result of libraries 
'''
class Module: 
    def __init__(self, mod): 
        self.name = mod.name
        self.base = mod.base_addr 
        self.end = mod.base_addr + mod.size
        self.filepath = mod.file
'''

class Address: 
    def __init__(self, module, offset):
        self.module = module
        self.offset = offset

class Edge:
    def __init__(self, addresses, hit_count): 
        self.addresses = addresses
        self.hit_count = hit_count 

def in_range(x, rng):
    (rng_start, rng_len) = rng
    if (x >= rng_start) and (x <= (rng_start + rng_len)):
        return True
    return False

                                
# True iff i1 is wholly within i2
def subsumed(i1, i2):
    (s1,l1) = i1
    (s2,l2) = i2
    if (s1 >= s2) and ((s1+l1) <= (s2+l2)):
        return True
                

def get_module_offset(pc, modules):
    for mn in modules.keys():
        module_range = modules[mn]
        if in_range(pc, module_range):
            return (mn, pc - module_range[0])
    return None



 
def create_recording(cfg, inputfile): 
    
    # Copy directory needed to insert into panda recording
    # We need the inputfile and we need the target binary install directory
    
    copydir = "./copydir"
    subdir = "install"
    if os.path.exists(copydir):
        shutfil.rmtree(copydir)
    os.makedirs(copydir) 
    shutil.copy(inputfile, copydir)
    shutil.copytree(target_dir, "%s/%s" % (copydir, subdir)) 

    # Get the qcow file 
    qcow = cfg.coverage.qcow;
    qcowfile = basename(qcow)
    qcf = "/qcows/%s" % qcowfile 
    assert(os.path.isfile(qcf))

    # Create panda recording if it does not already exist
    replayname = "%s/%s" % (replay_dir, basename(inputfile) + "-panda") 
    print("Replay name = [%s]" % replayname)

    args = cfg.coverage.args
    args = args.replace("file", "~/%s/%s" % (basename(copydir), basename(inputfile)), 1) 
    cmd = "cd %s/%s/ && ./%s %s" % (basename(copydir), subdir, cfg.target.name, args)
    print(cmd)
    
    exists_replay_name = ("%s%s" % (replayname, "-rr-snp")) 
    extra_args = ["-display", "none", "-nographic"] 
    
    if (os.path.exists(exists_replay_name)): 
        print("Recording %s exists" % exists_replay_name)
        extra_args.extend(["-loadvm", "root"]) 

    panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", 
            qcow=qcf, mem="1G", extra_args="-display none -nographic ") 

    @blocking
    def take_recording():
        panda.record_cmd(cmd, copydir, recording_name=replayname)
        panda.stop_run()


    panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
    if not os.path.exists(exists_replay_name): 
        print("Recording does not exist. Creating recording.")
        panda.queue_async(take_recording)
        panda.run()
    return replayname  

def run_replay(panda, plugins, old_plugins, plog_filename, replayname):
    # Now insert the plugins and run the replay
    for plugin in old_plugins:
        panda.unload_plugin(plugin)
    panda.set_pandalog(plog_filename)
    for plugin in plugins:
        panda.load_plugin(plugin, args=plugins[plugin]) 
    panda.run_replay(replayname)


def ingest_log_for_asid(cfg, plog_file):

    xm = None
    modules = {}
    base_addr = 0xffffffffffffffff
    program = cfg.target.name 

    print("Ingesting pandalog with asids and libs -- %d bytes" % (getsize(plog_file)))
    with plog.PLogReader(plog_file) as plr:
        try:
            for i, log_entry in enumerate(plr):
                if log_entry.HasField("asid_info"): 
                    ai = log_entry.asid_info
                    if ai.name == program and ai.asid < 0xffffffff:
                        if xm is None: 
                            xm = (ai.asid, ai.end_instr - ai.start_instr) 
                        else:
                            (asid, span) = xm
                            if ai.end_instr - ai.start_instr > span:
                                xm = (ai.asid, ai.end_instr - ai.start_instr) 
                if log_entry.HasField("asid_libraries"): 
                    for mod in log_entry.asid_libraries.modules:
                        if (mod.name == "[???]"):
                            continue 
                        name = mod.name
                        if not (name in modules): 
                            modules[name] = []
                        p = (mod.base_addr, mod.size) 
                        modules[name].append(p)
                        if mod.name == program and mod.base_addr < base_addr:
                            base_addr = mod.base_addr

        except Exception as e:
            print (str(e))

    new_modules = {}
    for name in modules.keys():
        print (name)
        # this discards exact duplicates
        ml = list(set(modules[name]))
        new_ml = []
        l = len(ml)
        for i in range(l-1): # for each range that the module is split into
            m1 = ml[i]
            # if m1 is subsumed by ANY of the modules
            # *later* in the list ml then we discard it                 
            subsumed_by_any = False
            for j in range(i+1,l): # check this one with the remainder 
                m2 = ml[j]
                if subsumed(m1,m2):
                    subsumed_by_any=True
                    break
            if not subsumed_by_any:
                new_ml.append(m1)
        ml = new_ml

        # order them by base addr
        def get_first(a):
            return a[0]
        ml.sort(key = get_first)

        # renaming to xmllint-1, xmllint-2, etc
        i = 1
        for m in ml:
            new_modules["%s-%d" % (name,i)] = m
            i += 1

    # discard that old modules list.  
    modules = new_modules
    
    print("Printing all the modules:")
    for module in modules: 
        print(module)
        print(modules[module])

    if xm is None: 
        print("Could not find asid") 
    else:
        (the_asid, the_range) = xm
        print("Asid is %d" % the_asid) 

    if base_addr == 0xffffffffffffffff:
        print ("Could not find base addr") 
    else:
        print("Base addr is 0x%x" % base_addr)

    return [the_asid, base_addr, modules] 

def ingest_log(cfg, asid, modules, plog_file):
    #plog_file = "%s/%s" % (os.getcwd(), plog_file_name)
    #plog_file = "/working/outputs/2020-05-28/22-06-52/2coverage.plog" 
    edges = [] 
    resolved_edges = []
    print("Ingesting pandalog with edge_coverage -- %d bytes" % (getsize(plog_file)))
    with plog.PLogReader(plog_file) as plr: 
        try: 
            for i, log_entry in enumerate(plr):
                if log_entry.HasField("edge_coverage"):
                    assert log_entry.HasField("asid")
                    if not (log_entry.asid == asid): 
                        continue
                    for edge in log_entry.edge_coverage.edges:
                        if len(edge.pc) < 2: # lets ignore basic blocks 
                            continue 
                        addresses = []
                        not_found = False
                        for pc in edge.pc: 
                            #print(pc)
                            m = get_module_offset(pc, modules) # m is the (module name, offset) for the pc 
                            if m is None:
                                print(" did not find a (mod, offset) for this pc: %d" % pc) 
                                not_found = True
                                break # if any dont have, we dont include the edge as a whole 
                            addresses.append(Address(m[0], m[1]))
                        if not not_found:
                            resolved_edges.append(Edge(addresses, edge.hit_count))

        except Exception as e:
            print (str(e))

    return resolved_edges


def send_to_database(kb_analysis, edge_list, input_file, module_list, stub): 
    
    
    # Add the modules first 
    modules = []
    for name in module_list: 
        (base_addr, size) = module_list[name]
        module = kbp.Module(name=name, base=base_addr, end=base_addr + size, filepath=name) # this will be fixed at a later time 
        modules.append(module)
    print("Sending %d modules" % len(modules))
    kbp_modules = {r.name:r for r in stub.AddModules(iter(modules))} 

    # Add our input next 
    old_kb_input = stub.GetInput(kbp.Input(filepath=input_file)) 
    old_kb_input.coverage_complete = True
    old_kb_input.pending_lock = False 
    kb_input = stub.AddInput(old_kb_input)

    edges = []
    addresses = []
    new_edges = 0
    for edge in edge_list:
        addrs = [kbp.Address(module=kbp_modules[a.module], offset=a.offset) for a in edge.addresses]
        kb_addrs = [r for r in stub.AddAddresses(iter(addrs))]
        # Does the edge exist? 
        kb_edge = None
        kbp_edge = kbp.Edge(address=kb_addrs)
        result = stub.EdgeExists(kbp_edge)
        if not result.success: # Does not exist
            # New Edge Event Found
            new_edges += 1
            kb_edge = stub.AddEdge(kbp_edge)
            te = kbp.NewEdgeEvent(edge=kb_edge) 
            stub.AddFuzzingEvent(kbp.FuzzingEvent(
                analysis=kb_analysis.uuid, input=kb_input.uuid, 
                new_edge_event=te))
        else:
            kb_edge = stub.AddEdge(kbp_edge)

        edges.append(kbp.EdgeCoverage(hit_count=edge.hit_count, edge=kb_edge, input=kb_input))
    for r in stub.AddEdgeCoverage(iter(edges)):
        pass

    print("%d new edges out of %d edges found" % (new_edges, len(edges)))





def check_analysis_complete(cfg, kbs, inputfile):


    # get canonical representations for all of these things
    target_msg = kbp.Target(name=cfg.target.name, \
                            source_hash=cfg.target.source_hash)
    target = kbs.AddTarget(target_msg)
    
    panda_msg = kbp.AnalysisTool(name=cfg.coverage.panda_container, \
                               source_string=cfg.coverage.source_string,
                               type=kbp.AnalysisTool.AnalysisType.COVERAGE)
    panda = kbs.AddAnalysisTool(panda_msg)

    print("input file is [%s]" % inputfile) 
    coverage_input = kbs.GetInput(kbp.Input(filepath=inputfile))

    # if we have already performed this coverage analysis, bail
    coverage_analysis_msg = kbp.Analysis(tool=panda.uuid, \
                                      target=target.uuid, \
                                      input=coverage_input.uuid)
    coverage_analysis = kbs.AddAnalysis(coverage_analysis_msg)


    msg_end =  "\ntool[%s]\ntarget[%s]\ninput[%s]" \
          % (text_format.MessageToString(panda), \
             text_format.MessageToString(target), \
             text_format.MessageToString(coverage_input))
    
    if coverage_analysis.complete:
        log.info("Coverage analysis already performed for %s" % msg_end)
        return [True, None, coverage_analysis]
    
    log.info("Coverage analysis proceeding for %s" % msg_end)
    return [False, coverage_input, coverage_analysis] 







@hydra.main(config_path=f"{spitfire_dir}/config/expt1/config.yaml")
def run(cfg):    
    
    # Get the input file
    input_file = cfg.coverage.input_file 

    # Add the analysis 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        
        log.info("Connected to knowledge_base")

        kbs = kbpg.KnowledgeBaseStub(channel)
        
        [complete, kb_input, kb_analysis] = check_analysis_complete(cfg, kbs, input_file)
        if complete:   
            return

        # Add the timing event 
        te = kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS, 
            event=kbp.TimingEvent.Event.BEGIN) 
        kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
            input=kb_input.uuid, timing_event=te)) 
    
    # Get the plog file
    plog_file_name = cfg.coverage.plog_file_name

    # Create the recording
    replayname = create_recording(cfg, input_file) 
    
    panda_dir = "/panda" 
    arch = "x86_64" 
    
    panda = join(join(join(panda_dir,"build"), "%s-softmmu" % arch), "panda-system-%s" % arch)
    general_panda_args = " -m 1G -os linux-64-ubuntu:4.15.0-72-generic" 
    rfpfx = join(replay_dir, "%s-panda" % basename(input_file))

    plog_file = "%s/%s" % (os.getcwd(), plog_file_name)
    panda_cmd = panda + general_panda_args + (" -replay %s" % rfpfx) \
                + (" -pandalog %s" % plog_file) \
                + " -panda asidstory" \
                + (" -panda loaded_libs:program_name=%s" % cfg.target.name)  
    print(panda_cmd)
    sp.call(panda_cmd.split())
  
    if os.path.getsize(plog_file) == 0: 
        print("PLOG 1 IS 0") 
    print("Size of plog file: %d" % os.path.getsize(plog_file))

    [asid, base_addr, modules] = ingest_log_for_asid(cfg, plog_file) 
    plog_file = "%s/%s" % (os.getcwd(), "2" + plog_file_name)
    panda_cmd = panda + general_panda_args + (" -replay %s" % rfpfx) \
                + (" -pandalog %s" % plog_file) \
                + (" -panda general:program_name=%s" % cfg.target.name) \
                + (" -panda edge_coverage:n=2,main=%x" % (base_addr + int(cfg.target.main_addr, 0)))
    
    print(panda_cmd)
    sp.call(panda_cmd.split())
    
    if os.path.getsize(plog_file) == 0: 
        print("PLOG 2 IS 0") 

    edges = ingest_log(cfg, asid, modules, plog_file)
    
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        print("here: connected");
        
        stub = kbpg.KnowledgeBaseStub(channel) 
        send_to_database(kb_analysis, edges, input_file, modules, stub) 

        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS, 
                event=kbp.TimingEvent.Event.END) 
        stub.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
            input=kb_input.uuid, timing_event=te))

            
if __name__ == '__main__':
    logging.basicConfig()
    run()
