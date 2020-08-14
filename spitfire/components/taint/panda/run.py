"""

Create recording.  Run replay with taint analysis.  Ingest results to knowledge base

Note: knowledge base server must be up and running and initialized.  

Usage:

panda_taint.py 

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

namespace = os.environ.get("NAMESPACE") 
spitfire_dir = "/%s%s" % (namespace, os.environ.get('SPITFIRE_DIR')) #"/spitfire" # Env variable
replaydir = "/%s%s" % (namespace, os.environ.get('REPLAY_DIR')) # make this env variable 
targetdir = "/%s%s" % (namespace, os.environ.get('TARGET_DIR')) # "/install" # Env variable  

sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")

assert (not (spitfire_dir is None)) 
import knowledge_base_pb2 as kbp 
import knowledge_base_pb2_grpc as kbpg
import knowledge_base
import plog_pb2
from taint_analysis import * 
from google.protobuf import text_format 
from capstone import * 
# Get the environment

# Functions

def tick():
    global last_time
    last_time = time.time()
    print(last_time)

def tock():
    return time.time() - last_time

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

def get_instr_type_bytes(target_pc, basic_blocks): 
    typ = None
    byte = None
    for pc in basic_blocks:
        for bb in basic_blocks[pc]:
            if target_pc in range(bb.start, bb.end): 
                bb_offset = target_pc - bb.start
                bb_byte = bb.code[bb_offset:]
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.details = True
                for i in md.disasm(bb_byte, 0x1000): #int(tiv.pc).ToString("X")):
                    typ = i.mnemonic 
                    byte = i.bytes
                    return (typ, byte) 
    return None 

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

# Class to contain result of libraries 
'''
class Module: 
    def __init__(self, mod): 
        self.name = mod.name
        self.base = mod.base_addr 
        self.end = mod.base_addr + mod.size
        self.filepath = mod.file
'''

class BasicBlock:
    def __init__(self, bb): 
        self.start = bb.pc
        self.end = bb.pc + bb.basic_block.size
        self.code = bb.basic_block.code 

import shutil

log = logging.getLogger(__name__)

# this should really be argv[1]
fuzzing_config_dir = "%s/config/expt1" % spitfire_dir  # Can you send this in as an argument? 


def create_recording(cfg, inputfile, plog_filename): 
    

    # Copy directory needed to insert into panda recording
    # We need the inputfile and we need the target binary install directory
    copydir = "./copydir"
    subdir = "install"
    if os.path.exists(copydir):
        shutfil.rmtree(copydir)
    os.makedirs(copydir) 
    shutil.copy(inputfile, copydir)
    shutil.copytree(targetdir, "%s/%s" % (copydir, subdir)) 

    # Get the qcow file 
    qcow = cfg.taint.qcow;
    qcowfile = basename(qcow)
    qcf = "/qcows/%s" % qcowfile 
    assert(os.path.isfile(qcf))

    # Create panda recording
    replayname = "%s/%s" % (replaydir, basename(inputfile) + "-panda") 
    print("replay name = [%s]" % replayname)

    # This needs to be changed
    args = cfg.taint.args 
    args = args.replace("file", "~/%s/%s" % (basename(copydir), basename(inputfile)), 1) 
    print(args) 
    cmd = "cd %s/%s/ && ./%s %s" % (basename(copydir), subdir, cfg.target.name, args)
    print(cmd) 
    exists_replay_name = ("%s%s" % (replayname, "-rr-snp"))
    extra_args = ["-display", "none", "-nographic"] 
    if (os.path.exists(exists_replay_name)):
        extra_args.extend(["-loadvm", "root"]) 
    
    print(replayname)
    panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", 
            qcow=qcf, mem="1G", extra_args=extra_args) 

    @blocking
    def take_recording():
        panda.record_cmd(cmd, copydir, recording_name=replayname)
        panda.stop_run()

    panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
    
    if not os.path.exists(exists_replay_name): 
        log.info("Creating recording")
        panda.queue_async(take_recording)
        panda.run()

    return [panda, replayname] 

    

def run_replay(panda, plugins, plog_filename, replayname):
    # Now insert the plugins and run the replay
    panda.set_pandalog(plog_filename)
    for plugin in plugins:
        panda.load_plugin(plugin, args=plugins[plugin]) 
    panda.run_replay(replayname)



def ingest_log_for_asid(cfg, plog_file_name):
    plog_file = "%s/%s" % (os.getcwd(), plog_file_name)
    #plog_file = "/outputs/2020-05-29/02-38-03/taint.plog"  
    xm = None
    modules = {}
    base_addr = 0xffffffffffffffff
    program = cfg.target.name 

    print("Ingesting pandalog") 
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

    return [the_asid, modules] 



def collect_code(log_entry, basic_blocks): 
    bb = log_entry.basic_block
    if not (bb.asid in basic_blocks):
        basic_blocks[bb.asid] = {}
    if not (log_entry.pc in basic_blocks[bb.asid]):
        basic_blocks[bb.asid][log_entry.pc] = [] #set([])
    #block = [bb.size, bb.code]
    block = BasicBlock(log_entry)
    basic_blocks[bb.asid][log_entry.pc].append(block)



def collect_taint(cfg, log_entry, tainting_fbs): 
    ti = log_entry.tainted_instr
    tq = ti.taint_query
    num_bytes = len(tq)
    tiv = TaintedInstrValue(log_entry)
    # Discard if label set too big
    if len(tiv.labels) > cfg.taint.max_label_set_size:
        return
    # as long as at least one byte in this tainted instr val
    # has tcn less than max then there is something 
    # we may be able to control
    if tiv.tcn_min < cfg.taint.max_label_set_compute_distance:
        if not (tiv.labels in tainting_fbs):
            tainting_fbs[tiv.labels] = set([])
        tainting_fbs[tiv.labels].add(tiv)


def exclude_fbs(cfg, tainting_fbs):
    # determine set of fbs to exclude.
    # exclude any that taint too many unique pcs

    excluded_fbs = set([])
    for fbs in tainting_fbs.keys():
        pcs_for_this_fbs = set([])
        for tiv in tainting_fbs[fbs]:
            pcs_for_this_fbs.add(tiv.pc)
        if fbs == frozenset([0]):
            print (pcs_for_this_fbs)
        if len(pcs_for_this_fbs) > cfg.taint.max_pcs_for_an_fbs:
            excluded_fbs.add(fbs)

    print ("excluding %d fbs since they taint too many pcs" % (len(excluded_fbs)))
    return excluded_fbs


def exclude_pcs(cfg, tainting_fbs): 
    # determine set of pcs to exclude
    # exclude any that are tainted by too many distinct fbs

    fbs_for_pc = {}
    for fbs in tainting_fbs.keys():
        for tiv in tainting_fbs[fbs]:
            if not (tiv.pc in fbs_for_pc):                
                fbs_for_pc[tiv.pc] = set([])
            fbs_for_pc[tiv.pc].add(fbs)

    excluded_pcs = set([])
    for pc in fbs_for_pc.keys():
        if len(fbs_for_pc[pc]) > cfg.taint.max_fbs_for_a_pc:
            excluded_pcs.add(pc)

    print ("Excluding %d pcs since they are tainted by too many fbs" % (len(excluded_pcs)))
    return excluded_pcs 




def make_taint_analysis(tainting_fbs, excluded_fbs, excluded_pcs, modules, basic_blocks): #first_instr, last_instr): 
    print ("Constructing spitfire TaintAnalysis")

    ta = TaintAnalysis()
    excluded_ti_1 = 0
    excluded_ti_2 = 0
    excluded_fbs_1 = 0
    excluded_fbs_2 = 0
    
    for fbs in tainting_fbs.keys():
        if fbs in excluded_fbs: 
            excluded_fbs_1 += 1
            excluded_ti_1 += len(tainting_fbs[fbs])
            continue
        num_pcs = 0
        for tiv in tainting_fbs[fbs]:
            if tiv.pc in excluded_pcs:
                excluded_ti_2 += 1
                continue
            num_pcs +=1
        if num_pcs == 0:
            excluded_fbs_2 += 1
            continue

        not_found = False
        for tiv in tainting_fbs[fbs]:
            if tiv.pc in excluded_pcs:
                continue

            # Get the module and offset
            m = get_module_offset(tiv.pc, modules) 
            if m is None:
                print("did not find a (mod, offset for this pc: %d", tiv.pc)
                not_found = True
                continue
            (module, mod_offset) = m
            
            # Get the type and bytes of the instr
            b = get_instr_type_bytes(tiv.pc, basic_blocks) 
            if b is None: 
                print("Unable to find the bb for pc %d", tiv.pc) 
                continue

            (typ, byte) = b

            f = FuzzableByteSet(fbs)
            i = TaintedInstruction(mod_offset, module, typ, byte) #None) #tiv.pc, "Unk", None)
            #print(i)
            tm = TaintMapping(f, i, 42, tiv.len, 0, 
                    #(float(tiv.instr - first_instr) / (last_instr - first_instr)), 
                    tiv.tcn_min, tiv.tcn_max)
            ta.add_taint_mapping(tm)
            #print(tiv.pc)
            #print(typ)
            #print(byte)
            #print(module)
            #print(mod_offset)
    print ("------------------------")
    print("Excluded %d ti because they are in a forbidden fbs" % excluded_ti_1)
    print("Excluded %d ti because they are a forbidden pc" % excluded_ti_2)
    print("Excluded %d fbs because they are a forbideen fbs" % excluded_fbs_1)
    print("Excluded %d fbs because they have only forbidden pcs" % excluded_fbs_2)
    
    return ta



def ingest_log_to_taint_obj(cfg, asid, modules, plog_filename):
    program = cfg.target.name # the name of the program 
    plog_file = "%s/%s" % (os.getcwd(), plog_filename) 
    
    # Information to track 
    basic_blocks = {}
    tainting_fbs = {} # fbs -> TaintedInstrValues, where fbs is fuzzable byte set
    
    num_bb = 0
    num_ti = 0
    
    # Ingest Pandalog 
    print ("Ingesting pandalog")
    with plog.PLogReader(plog_file) as plr:
        try:
            for i, log_entry in enumerate(plr):
                last_instr = log_entry.instr

                # Collect basic block information for program counters and asids
                if log_entry.HasField("basic_block"):
                    num_bb += 1
                    collect_code(log_entry, basic_blocks) #, basic_blocks) 
                
                # Collect taint information 
                if log_entry.HasField("tainted_instr"):
                    num_ti += 1
                    collect_taint(cfg, log_entry, tainting_fbs)
        
        except Exception as e: 
            print (str(e))

    print("Number of bb entries: %d" % num_bb)
    print("Number of ti entries: %d" % num_ti)
    print ("Found %d tainting fuzzable byte sets (fbs)" % (len(tainting_fbs)))
    sum_ti = 0;
    for fbs in tainting_fbs:
        sum_ti += len(tainting_fbs[fbs])
    print("Number of ti entires kept: %d" % sum_ti)
    print ("Number of basic blocks in program: %d" % len(basic_blocks))

    basic_block = basic_blocks[asid] #None
    print("Number of bb for asid: %d" % len(basic_block))

    # Determine set of fbs and pcs to exclude.
    excluded_fbs = exclude_fbs(cfg, tainting_fbs) 
    excluded_pcs = exclude_pcs(cfg, tainting_fbs) 
    fm = make_taint_analysis(tainting_fbs, excluded_fbs, excluded_pcs, modules, basic_block)
    return fm 




def byte_uuid(uuid):
    return bytes(uuid, 'utf-8')

# Ta is the TaintAnalysis 
def send_to_database(kb_analysis, ta, old_kb_input, module_list, stub): 

    old_kb_input.taint_analyzed = True
    old_kb_input.pending_lock = False
    kb_input = stub.AddInput(old_kb_input)

    taint_mappings = []
    fuzzable_byte_sets = [] 
    tainted_instructions = []
    addresses = []
    module_dict = {}

    modules = []
    for name in module_list: 
        (base_addr, size) = module_list[name]
        module = kbp.Module(name=name, base=base_addr, end=base_addr + size, filepath=name)
        modules.append(module) 

    print("Sending %d modules" % len(modules))
    kb_modules = {r.name:r for r in stub.AddModules(iter(modules))} 
    
    for tm in ta.tma:
        ti = tm.ti
        if not ti.module in kb_modules: 
            print("problem")
            continue
        module = kb_modules[ti.module]

    addresses = [kbp.Address(module=kb_modules[tm.ti.module], offset = tm.ti.pc) for tm in ta.tma] 
    kb_addresses = [r for r in stub.AddAddresses(iter(addresses))]
    print("Added %d addresses" % len(kb_addresses))

    tis = [kbp.TaintedInstruction(address=kb_addresses[i], type=tm.ti.type, instruction_bytes=bytes(tm.ti.bytes)) 
            for i,tm in enumerate(ta.tma)]
    # Before we add the Tainted Instructions lets see if they already exist
    ti_exists = [(stub.TaintedInstructionExists(ti)).success for ti in tis]
    kb_ti = [r for r in stub.AddTaintedInstructions(iter(tis))]
    #print("Added %d tainted instructions" % len(kb_ti))
    new_ti = 0
    for i, exists in enumerate(ti_exists): 
        if not exists: 
            new_ti += 1
            # Found a new TI
            te = kbp.NewTaintedInstructionEvent(instruction=tis[i]) 
            stub.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
                input=kb_input.uuid, new_tainted_instruction_event=te))

    print("Added %d new ti out of %d tainted instructions" % (new_ti, len(kb_ti)))
    fbs = [kbp.FuzzableByteSet(label=tm.fbs.labels) for tm in ta.tma]
    kb_fbs = [r for r in stub.AddFuzzableByteSets(iter(fbs))]
    print("Added %d fbs" % len(kb_fbs))

    tm = [kbp.TaintMapping(input=kb_input, fuzzable_byte_set=kb_fbs[i], tainted_instruction=kb_ti[i], \
            value=tm.value, value_length=tm.value_length, \
            min_compute_distance=tm.min_compute_distance, max_compute_distance=tm.max_compute_distance)
            for i, tm in enumerate(ta.tma)]
    
    for r in stub.AddTaintMappings(iter(tm)):
        pass
    #print(r)
    #r = stub.AddTaintMappings(iter(tm))
    print(len(ta.tma))
 

def check_analysis_complete(cfg, kbs, inputfile):

    # get canonical representations for all of these things
    target_msg = kbp.Target(name=cfg.target.name, \
                            source_hash=cfg.target.source_hash)
    target = kbs.AddTarget(target_msg)
    
    panda_msg = kbp.AnalysisTool(name=cfg.taint.panda_container, \
                               source_string=cfg.taint.source_string,
                               type=kbp.AnalysisTool.AnalysisType.TAINT)
    panda = kbs.AddAnalysisTool(panda_msg)

    print("input file is [%s]" % inputfile) 
    taint_input = kbs.GetInput(kbp.Input(filepath=inputfile))

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
        return [True, None, taint_analysis]
    
    log.info("Taint analysis proceeding for %s" % msg_end)
    return [False, taint_input, taint_analysis] 


@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def run(cfg):
    tick()

    # Make sure the target directory is a directory
    assert(os.path.isdir(targetdir))

    # Get the input file
    inputfile = cfg.taint.input_file 
    
    # Send over some preliminary data to check if we have done this taint before 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        
        log.info("Connected to knowledge_base")

        kbs = kbpg.KnowledgeBaseStub(channel)
        
        [complete, kb_input, kb_analysis] = check_analysis_complete(cfg, kbs, inputfile)
        if complete:   
            return

        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                event=kbp.TimingEvent.Event.BEGIN)
        kbs.AddFuzzingEvent(kbp.FuzzingEvent(analysis=kb_analysis.uuid,
                input=kb_input.uuid,timing_event=te))
    
    # Get the plog filename 
    plog_file_name = cfg.taint.plog_filename
    
    # Run the panda recording
    [_, replayname] = create_recording(cfg, inputfile, plog_file_name)

    #plugins = {}
    #plugins["asidstory"] = {}
    #plugins["loaded_libs"] = {"program_name": cfg.target.name}
    #run_replay(panda, plugins, plog_file_name, replayname) 
    
    panda_dir = "/panda" 
    arch = "x86_64" 
    
    panda = join(join(join(panda_dir,"build"), "%s-softmmu" % arch), "panda-system-%s" % arch)
    general_panda_args = " -m 1G -os linux-64-ubuntu:4.15.0-72-generic" 
    rfpfx = join(replaydir, "%s-panda" % basename(inputfile))

    plog_file = "%s/%s" % (os.getcwd(), plog_file_name)
    panda_cmd = panda + general_panda_args + (" -replay %s" % rfpfx) \
                + (" -pandalog %s" % plog_file) \
                + " -panda asidstory" \
                + (" -panda loaded_libs:program_name=%s" % cfg.target.name)  
    print(panda_cmd)
    sp.call(panda_cmd.split())
    
    #[asid, base_addr, modules] = ingest_log_for_asid(cfg, plog_file_name) 

    [asid, modules] = ingest_log_for_asid(cfg, plog_file_name)
    print(asid)
    print(modules)
    
   # plugins.clear()
   # plugins["tainted_instr"] = {}
   # plugins["collect_code"] = {}
   # plugins["tainted_branch"] = {} 
   # plugins["file_taint"] = {"filename": "/root/copydir/"+basename(inputfile), "pos": "1"}
   # run_replay(panda, plugins, "2" + plog_file_name, replayname) 
    plog_file = "%s/%s" % (os.getcwd(), "2" + plog_file_name)
    panda_cmd = panda + general_panda_args + (" -replay %s" % rfpfx) \
                + (" -pandalog %s" % plog_file) \
                + (" -panda tainted_instr") \
                + (" -panda tainted_branch") \
                + (" -panda collect_code") \
                + (" -panda file_taint:filename=/root/copydir/%s,pos=1" % (basename(inputfile))) 
    
    print(panda_cmd)
    sp.call(panda_cmd.split())
    

    fm = ingest_log_to_taint_obj(cfg, asid, modules, "2" + plog_file_name) 
    
    # Send the information over to the database 
    with grpc.insecure_channel('%s:%d' % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
    
        stub = kbpg.KnowledgeBaseStub(channel) #spitire_pb2_grpc.SpitfireStub(kb_channel)
        
        send_to_database(kb_analysis, fm, kb_input, modules, stub)
        
        te =  kbp.TimingEvent(type=kbp.TimingEvent.Type.ANALYSIS,
                              event=kbp.TimingEvent.Event.END)        
        stub.AddFuzzingEvent(
            kbp.FuzzingEvent(analysis=kb_analysis.uuid, 
                input=kb_input.uuid,
                             timing_event=te))
    
    print("%d seconds" % tock()) 



if __name__ == "__main__":
    run()
    log.info("panda_taint.py finished")

