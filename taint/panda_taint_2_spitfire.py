"""

Generates Spitfire TaintAnalysis tool output from PANDA replay 
run with taint analysis. 

Input is protobuf msgs from pandalog when PANDA is run on a replay 
with a bunch of plugins.  Note: pandalog is output as just straight
protobuf output (not plog).

Output is protobuf msgs too, but in format required by Spitfire's 
taint_analysis.proto.

PANDA should have been run with all of the following plugins.

asidstory         In non-summary mode so we get AsidInfo msgs for 
                  whenever process changes

collect_code      To get BasicBlock msgs that give us binary for 
                  all code that runs.  This is needed in order to 
                  know what kind of instruction is tainted, i.e.,
                  a load or jmp or compare or whatever.

file_taint        This isn't a required plugin in the sense that 
                  we don't look for any of its pandalog msgs.
                  However, something needs to apply taint labels.
                  Note, further, that file_taint should have been
                  run with pos=1 argument so that we get a taint
                  labels corresponding to file offsets.

tainted_instr     This creates a pandalog entry whenever the state
                  of the taint system changes. This is when taint
                  label sets associated with register or memory bytes
                  are deleted (untainting) or copied, as well as when
                  computation happens (such as a = b+c, where b and c are 
                  both tainted and have different label sets associated 
                  with their bytes). This plugin generates a TaintedInstr 
                  msg for each 'value' seen to experience a taint change.  
                  A value is a machine register or extent in physical memory. 
                  For a 4-byte register, e.g., this will generate up to four
                  TaintQuery messages (if all four bytes are tainted) and 
                  collect them under the TaintedInstr msg. Each TaintQuery 
                  will indicate the set of labels (and thus input bytes) seen 
                  to taint that intruction value byte.


The output of this script is in terms of the following three msg types.

SfFuzzableByteSet      The set of taint labels seen, collectively, to taint
                       some value used by an instruction. This is the union 
                       of all labels from all TaintQuerys for a TaintedInstr.
                       For positional file_taint, this means the set of input
                       bytes by position in the file.

SfTaintedInstruction   This is the instruction involved in a TaintQuery and
                       the msg tells us what kind of instruction as well as pc.
                      
SfTaintMapping         This msg corresponds to a single TaintedInstr msg and
                       thus connects a SfFuzzableByteSet to a 
                       SfTaintedInstruction. Additionally, it provides info 
                       such as when this was observed in the program trace, 
                       some indication of the computational distance between 
                       input bytes and tainted instruction value bytes.


This script filters the taint info output by PANDA based upon a few parameters.

max_label_set_size     If the cardinality of a taint label set for some
                       queried byte is too large, we discard that taint 
                       information on the grounds that the influence is
                       too weak.

max_label_set_compute_distance

                       If the computational distance between inputs bytes and
                       a taint label set representing a tainted instruction 
                       value is too large, we discard that taint set, 
                       on the grounds that it is computationally too far 
                       from the input to be likely controllable.

max_fbs_for_a_pc       If too many unique SfFuzzableByteSets are seen to 
                       taint the instruction at some program counter, we
                       exclude the corresponding SfTaintedInstruction from 
                       output, since that instruction has too many input
                       bytes controlling it.

max_pcs_for_an_fbs     If too many SfTaintedInstructions are associated
                       with a set of fuzzable bytes, then we exclude that
                       SfFuzzableByteSet from the output, as that part of
                       the input seems to control too many different 
                       program instructions

"""


import sys
import itertools
import os
import struct
from os.path import dirname

from google.protobuf.json_format import MessageToJson


sys.path.append("/home/tleek/git/panda-spitfire/build/i386-softmmu")
import plog_pb2

from taint_analysis import *

# used to maintain a mapping from ptr -> labelset
ptr2labelset = {}

# class to contain result of a taint query
# of a value at an instruction in a trace
class TaintedInstrValue:

    def __init__(self, le):
        self.pc = le.pc

        if (le.pc >= 0x08048154 and le.pc <= 0x0804c0e0):
            print "le.pc = %x" % le.pc
        self.instr = le.instr
        # size of value, in bytes
        ti = le.tainted_instr
        self.len = len(ti.taint_query)
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
        return "pc=%x instr=%x len=%d tcn=%s labels=[%s]" % (self.pc, self.instr, self.len, tcnstr, self.labels)


            

the_program = "file-32"

panda_protobuf_in = sys.argv[1]


spitfire_protobuf_out = sys.argv[2]

max_label_set_size = 16
max_fbs_for_a_pc = 16
max_pcs_for_an_fbs = 16
max_label_set_compute_distance = 16

# used to collect asids for the_program
asids = set([])
# used to collect instr intervals for the_program
instr_intervals = []

basic_blocks = {}

# fbs -> TaintedInstrValues
# where fbs is fuzzable byte set
tainting_fbs = {}


ntq = 0

first_instr_for_program = None
last_instr_for_program = None

last_instr = None

# process the pandalog protobuf messages
with open(panda_protobuf_in, "rb") as pbf:

    while True:

        if ntq > 1 and (0 == (ntq % 100000)):
            print ntq

        if ntq > 50000:
            break
        
        try:

            # size of pb msg
            msg_size, = struct.unpack("I", pbf.read(4))
            
            log_entry = plog_pb2.LogEntry()
            log_entry.ParseFromString(pbf.read(msg_size))
            last_instr = log_entry.instr

            if log_entry.HasField("asid_info"):
                ai = log_entry.asid_info
                if ai.name == the_program:
                    asids.add(ai.asid)
                    instr_interval = [ai.start_instr, ai.end_instr]
                    instr_intervals.append(instr_interval)
                    if ai.name == the_program:
                        if first_instr_for_program is None:
                            first_instr_for_program = ai.start_instr
                        last_instr_for_program = ai.end_instr

            if log_entry.HasField("basic_block"):
                bb = log_entry.basic_block
                if not (bb.asid in basic_blocks):
                    basic_blocks[bb.asid] = {}
                if not (log_entry.pc in basic_blocks[bb.asid]):
                    basic_blocks[bb.asid][log_entry.pc] = set([])
                block = (bb.size, bb.code)
                basic_blocks[bb.asid][log_entry.pc].add(block)
                
            if log_entry.HasField("tainted_instr"):
                ti = log_entry.tainted_instr
                tq = ti.taint_query
                num_bytes = len(tq)
                tiv = TaintedInstrValue(log_entry)
                # discard if label set too big
                if len(tiv.labels) > max_label_set_size:
                    continue
                # as long as at least one byte in this tainted instr val
                # has tcn less than max then there is something 
                # we may be able to control
                if tiv.tcn_min < max_label_set_compute_distance:
                    if not (tiv.labels in tainting_fbs):
                        tainting_fbs[tiv.labels] = set([])
                    tainting_fbs[tiv.labels].add(tiv)
                ntq += 1

        except Exception as e: 
            print e
            break



print "Found %d tainting fuzzable byte sets (fbs)" % (len(tainting_fbs))


# determine set of fbs to exclude.
# exclude any that taint too many unique pcs
excluded_fbs = set([])
for fbs in tainting_fbs.keys():
    pcs_for_this_fbs = set([])
    for tiv in tainting_fbs[fbs]:
        pcs_for_this_fbs.add(tiv.pc)
    if len(pcs_for_this_fbs) > max_pcs_for_an_fbs:
        excluded_fbs.add(fbs)

print "excluding %d fbs since they taint too many pcs" % (len(excluded_fbs))

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
    if len(fbs_for_pc[pc]) > max_fbs_for_a_pc:
        excluded_pcs.add(pc)

print "excluding %d pcs since they are tainted by too many fbs" % (len(excluded_pcs))


# construct the spitfire taint analyiss
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
    print "fbs=%s" % (str(fbs))
    for tiv in tainting_fbs[fbs]:
        if tiv.pc in excluded_pcs:
            continue
        f = FuzzableByteSet(fbs)
        i = TaintedInstruction(tiv.pc, "Unk", None)
        tm = TaintMapping(f, i, 42, tiv.len, (float(tiv.instr - first_instr_for_program) / (last_instr_for_program - first_instr_for_program)), tiv.tcn_min, tiv.tcn_max)
        ta.add_taint_mapping(tm)

print "------------------------"
print ta

with open(spitfire_protobuf_out, "w") as s:
    ta.marshal(s)

with open(spitfire_protobuf_out, "r") as s:
    ta2 = unmarshal_taint_analysis(s)
    print "------------------------"
    print ta2
    
print "done"
