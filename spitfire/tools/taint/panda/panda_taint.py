"""

Create recording.  Run replay with taint analysis.  Ingest results to knowledge base

Note: knowledge base server must be up and running and initialized.  

Usage:

panda_taint.py fuzz_config input_filename



panda_taint.py /home/tleek/git/raf/spitfire/config/expt1 /home/tleek/transfer/libxml2/test/slashdot.xml


"""

# Imports
import sys
import logging
import os
from os.path import join,basename
import subprocess as sp
import grpc
import hydra
from panda import Panda, blocking
from panda import * 
import time
import itertools
spitfire_dir="/spitfire" # Env variable
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")
assert (not (spitfire_dir is None)) 
import spitfire.protos.knowledge_base_pb2 as kbp 
import spitfire.protos.knowledge_base_pb2_grpc as kbpg
import knowledge_base
import plog_pb2
from taint_analysis import * 
from google.protobuf import text_format 

# Functions

def tick():
    global last_time
    last_time = time.time()
    print(last_time)

def tock():
    return time.time() - last_time


# Class to containt result of a panda taint query
ptr2labelset = {}

class TaintedInstrValue:

    def __init__(self, le):
        self.pc = le.pc 
        self.instr = le.instr 
        ti = le.tainted_instr
        self.len = len(ti.taint_query) # number of bytes  
        self.tcn_max = 0
        self.tcn_min = 1000000 
        lbs = set([])
        for tbq in ti.taint_query:
            self.tcn_min = min(self.tcn_min, tbq.tcn)
            self.tcn_max = max(self.tcn_max, tbq.tcn)
            if tbq.HasField("unique_label_set"):
                uls = tbq.unique_label_set
                assert not (uls.ptr in ptr2labelset)
                ptr2labelset[uls.ptr] = set(uls.label)
            lbs = lbs.union(ptr2labelset[tbq.ptr])
        self.labels = frozenset(lbs)

    def __str__(self):
        if self.tcn_min == self.tcn_max:
            tcnstr = str(self.tcn_min)
        else:
            tcnstr = "[%d..%d]" % (self.tcn_min, self.tcn_max)
        return "pc=%x instr=%x len=%d tcn=%s labels=[%s]" \
                % (self.pc, self.instr, self.len, tcnstr, self.labels)


# Start script 
tick() 

# Get the qcow file
qcow = "http://panda-re.mit.edu/qcows/linux/ubuntu/1804/bionic-server-cloudimg-amd64.qcow2" # Config 
qcowfile = basename(qcow) 
qcf = "/panda-replays/targets/qcows/" + qcowfile 
assert(os.path.isfile(qcf))

# Target binary directory
installdir = "/install" # Env variable  
assert(os.path.isdir(installdir))

import shutil

log = logging.getLogger(__name__)

inputfile = os.environ.get('INPUT_FILE')
assert(os.path.exists(inputfile))
assert(os.path.isfile(inputfile))

# this should really be argv[1]
fuzzing_config_dir = "%s/config/expt1" % spitfire_dir  # Can you send this in as an argument? 


def create_and_run_recording(cfg, plog_filename): 
    
    log.info("Creating recording")

    # Copy directory needed to insert into panda recording
    # We need the inputfile and we need the target binary install directory
    copydir = "./copydir"
    if os.path.exists(copydir):
        shutfil.rmtree(copydir)
    os.makedirs(copydir) 
    shutil.copy(inputfile, copydir)
    shutil.copytree(installdir, copydir + "/install") 


    # Create panda recording
    replaydir = "/replay"
    replayname = replaydir + basename(inputfile) + "-panda"
    print("replay name = [%s]" % replayname)

    # This needs to be changed 
    cmd = "cd copydir/install/libxml2/.libs && ./xmllint ~/copydir/"+basename(inputfile)
    panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", 
            qcow=qcf, mem="1G", extra_args="-display none -nographic") 

    @blocking
    def take_recording():
        panda.record_cmd(cmd, copydir, recording_name=replayname)
        panda.stop_run()


    panda.queue_async(take_recording)
    panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
    panda.run()

    # Now insert the plugins and run the replay
    #plog_filename="taint.plog"
    panda.set_pandalog(plog_filename)
    panda.load_plugin("osi")
    panda.load_plugin("osi_linux")
    panda.load_plugin("tainted_instr")
    panda.load_plugin("asidstory")
    panda.load_plugin("collect_code")
    panda.load_plugin("tainted_branch")
    panda.load_plugin("file_taint", 
            args={"filename": "/root/copydir/"+basename(inputfile), "pos": "1"})

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


def collect_code(log_entry, basic_blocks): 
    bb = log_entry.basic_block
    if not (bb.asid in basic_blocks):
        basic_blocks[bb.asid] = {}
    if not (log_entry.pc in basic_blocks[bb.asid]):
        basic_blocks[bb.asid][log_entry.pc] = set([])
    block = (bb.size, bb.code)
    basic_blocks[bb.asid][log_entry.pc].add(block)



def collect_taint(log_entry, tainting_fbs): 
    max_label_set_size = 16
    max_label_set_compute_distance = 16
    
    ti = log_entry.tainted_instr
    tq = ti.taint_query
    num_bytes = len(tq)
    tiv = TaintedInstrValue(log_entry)
    # Discard if label set too big
    if len(tiv.labels) > max_label_set_size:
        return
        #continue
    # as long as at least one byte in this tainted instr val
    # has tcn less than max then there is something 
    # we may be able to control
    if tiv.tcn_min < max_label_set_compute_distance:
        if not (tiv.labels in tainting_fbs):
            tainting_fbs[tiv.labels] = set([])
        tainting_fbs[tiv.labels].add(tiv)
    return tainting_fbs 


def exclude_fbs(tainting_fbs):
    # determine set of fbs to exclude.
    # exclude any that taint too many unique pcs
    max_pcs_for_an_fbs = 16

    excluded_fbs = set([])
    for fbs in tainting_fbs.keys():
        pcs_for_this_fbs = set([])
        for tiv in tainting_fbs[fbs]:
            pcs_for_this_fbs.add(tiv.pc)
        if fbs == frozenset([0]):
            print (pcs_for_this_fbs)
        if len(pcs_for_this_fbs) > max_pcs_for_an_fbs:
            excluded_fbs.add(fbs)

    print ("excluding %d fbs since they taint too many pcs" % (len(excluded_fbs)))
    return excluded_fbs


def exclude_pcs(tainting_fbs): 
    # determine set of pcs to exclude
    # exclude any that are tainted by too many distinct fbs
    max_fbs_for_a_pc = 16

    fbs_for_pc = {}
    for fbs in tainting_fbs.keys():
        for tiv in tainting_fbs[fbs]:
            if not (tiv.pc in fbs_for_pc):                
                fbs_for_pc[tiv.pc] = set([])
            fbs_for_pc[tiv.pc].add(fbs)

    excluded_pcs = set([])
    for pc in fbs_for_pc.keys():
        if len(fbs_for_pc[pc]) > max_fbs_for_a_pc:
            excluded_pcs.add(pc)

    print ("excluding %d pcs since they are tainted by too many fbs" % (len(excluded_pcs)))
    return excluded_pcs 




def make_taint_analysis(tainting_fbs, excluded_fbs, excluded_pcs, first_instr, last_instr): 
    print ("Constructing spitfire TaintAnalysis")

    ta = TaintAnalysis()

    for fbs in tainting_fbs.keys():
        if fbs in excluded_fbs: 
            continue
        num_pcs = 0
        for tiv in tainting_fbs[fbs]:
            if tiv.pc in excluded_pcs:
                continue
            num_pcs +=1
        if num_pcs == 0:
            continue
        for tiv in tainting_fbs[fbs]:
            if tiv.pc in excluded_pcs:
                continue
            f = FuzzableByteSet(fbs)
            i = TaintedInstruction(tiv.pc, "Unk", None)
            print(float(tiv.instr))
            print(first_instr) #first_instr_for_program) 
            print(last_instr) #_for_program)
            tm = TaintMapping(f, i, 42, tiv.len,
                    (float(tiv.instr - first_instr) / (last_instr - first_instr)), 
                    tiv.tcn_min, tiv.tcn_max)
            ta.add_taint_mapping(tm)

    print ("------------------------")
    print (ta)
    return ta




def ingest_log_to_taint_obj(cfg, plog_filename):
    program = cfg.target.name # the name of the program 
    plog_file = "%s/%s" % (os.getcwd(), plog_filename) 
    print(plog_file)
    plog_file = "/spitfire/tools/taint/panda/outputs/2020-03-06/15-11-47/taint.plog"
    
    # Information to track 
    asids = set([])  #used to collect asids for the_program
    instr_intervals = [] # used to collect instr intervals for the_program
    basic_blocks = {}
    tainting_fbs = {} # fbs -> TaintedInstrValues, where fbs is fuzzable byte set
    
    first_instr_for_program = None
    last_instr_for_program = None
    last_instr = None
    
    # Ingest Pandalog 
    print ("Ingesting pandalog")
    with plog.PLogReader(plog_file) as plr:
        try:
            for i, log_entry in enumerate(plr):
                last_instr = log_entry.instr

                # Collect asids and instruction intervals for the target  
                if log_entry.HasField("asid_info"):
                    [first_instr_for_program, last_instr_for_program] = \
                    analyze_asid(log_entry, program, asids, instr_intervals, 
                            first_instr_for_program, last_instr_for_program)
                
                    # Collect basic block information for program counters and asids
                if log_entry.HasField("basic_block"):
                    collect_code(log_entry, basic_blocks) #, basic_blocks) 
                
                if log_entry.HasField("tainted_instr"):
                    collect_taint(log_entry, tainting_fbs) 
        
        except Exception as e: 
            print (str(e))
            #break

    print ("Found %d tainting fuzzable byte sets (fbs)" % (len(tainting_fbs)))
    print (len(asids))
    print (len(basic_blocks))
    print (len(instr_intervals))


    # Determine set of fbs and pcs to exclude.
    excluded_fbs = exclude_fbs(tainting_fbs) 
    excluded_pcs = exclude_pcs(tainting_fbs) 
    fm = make_taint_analysis(tainting_fbs, excluded_fbs, excluded_pcs, 
                first_instr_for_program, last_instr_for_program) 
    return fm 




def byte_uuid(uuid):
    return bytes(uuid, 'utf-8')

# Ta is the TaintAnalysis 
def send_to_database(ta, channel): 
    stub = kbpg.KnowledgeBaseStub(channel) #spitire_pb2_grpc.SpitfireStub(kb_channel)
     
    taint_mappings = []
    fuzzable_byte_sets = [] 
    tainted_instructions = []
    addresses = []
    modules = []

    for i, tm in enumerate(ta.tma):
        ti = tm.ti # Tainted Instruction
        fbs = tm.fbs # Fuzzable Byte Set 
        
        module = kbp.Module(name=ti.module)
        address = kbp.Address(module=module)
        tainted_instruction = kbp.TaintedInstruction(uuid=byte_uuid(ti_uuid), 
                address=address, type=ti.type)
        fuzzable_byte_set = kbp.FuzzableByteSet(uuid=byte_uuid(fbs_uuid), label=fbs.labels)
        taint_mapping = kbp.TaintMapping(fuzzable_byte_set=fuzzable_byte_set, 
                tainted_instruction=tainted_instruction, value=tm.value,
                value_length=tm.value_length, min_compute_distance=tm.min_compute_distance,
                max_compute_distance=tm.max_compute_distance)

        modules.append(module) 
        addresses.append(address)
        tainted_instructions.append(tainted_instruction)
        fuzzable_byte_sets.append(fuzzable_byte_set)
        taint_mappings.append(taint_mapping)

    
    result = stub.AddModules(iter(modules))
    result = stub.AddAddresses(iter(addresses))
    result = stub.AddTaintedInstructions(iter(tainted_instructions))
    print(result)
    result = stub.AddFuzzableByteSets(iter(fuzzable_byte_sets))
    print(result)
    result = stub.AddTaintMappings(iter(taint_mappings))
    print(result) 
    #modules.append(kbp.Module(name=ti.module)) 
        #addresses.append(kbp.Address(module=modules[i]))
        # what about uuid or base or end or filepath?
    print(len(ta.tma))
 


@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def run(cfg):
    # print(cfg.pretty())
    
    # channel to talk to kb server
    #with grpc.insecure_channel("%s:%s" % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
    with grpc.insecure_channel('%s:%d' % ("10.105.43.27", 61111)) as channel:
    #with grpc.insecure_channel('%s:%d' % ("localhost", 61113)) as channel:
        
        log.info("Connected to knowledge_base")

        kbs = kbpg.KnowledgeBaseStub(channel)

        # get canonical representations for all of these things
        target_msg = kbp.Target(name=cfg.target.name, \
                                source_hash=cfg.target.source_hash)
        target = kbs.AddTarget(target_msg)
        
        panda_msg = kbp.AnalysisTool(name="panda", \
                                   source_string=cfg.taint.source_string,
                                   type=kbp.AnalysisTool.AnalysisType.TAINT)
        panda = kbs.AddAnalysisTool(panda_msg)

        print("input file is [%s]" % inputfile) 
        input_msg = kbp.Input(filepath=inputfile) 
        taint_input = kbs.AddInput(input_msg)

        # if we have already performed this taint analysis, bail
        taint_analysis_msg = kbp.Analysis(tool=panda.uuid, \
                                          target=target.uuid, \
                                          input=taint_input.uuid)
        taint_analysis = kbs.AddAnalysis(taint_analysis_msg)

    
        msg_end =  "\ntool[%s]\ntarget[%s]\ninput[%s]" \
              % (text_format.MessageToString(panda), \
                 text_format.MessageToString(target), \
                 text_format.MessageToString(taint_input))

        if taint_analysis.complete:
            log.info("Taint analysis already performed for %s" % msg_end)
            return
        
        log.info("Taint analysis proceeding for %s" % msg_end)
    
    plog_filename = "taint.plog"
    #create_and_run_recording(cfg, plog_filename) 

    # Now marshall this infromatin over to the database 
    fm = ingest_log_to_taint_obj(cfg, plog_filename)
    
    with grpc.insecure_channel('%s:%d' % ("10.105.43.27", 61111)) as channel:
        send_to_database(fm, channel) 
    
    print("%d seconds" % tock()) 



if __name__ == "__main__":
    run()
    log.info("panda_taint.py finished")
