

"""
Spitfire class for taint analysis output in std form.

Idea is that python code that either generates or processes output of
a taint analysis would construct a TaintAnalysis object from a bunch
of FuzzableByteSet, TaintedInstruction, and TaintMapping objects, as
defined here.

The TaintAnalysis object can be marshaled (using its marshal method),
which writes it out as a sequence of protobuf messages.

That protobuf version of the taint analysis output can then be
consumed by the knowledge_base code to make it available and have it
persist.

"""

from enum import Enum
import struct

import sys
sys.path.append("../interfaces")
import taint_analysis_pb2


def marshal_len(f, l):
    packed_l = struct.pack('>L', l)
    f.write(packed_l)

def unmarshal_len(f):
    l_buf = f.read(4)
    return struct.unpack('>L', l_buf)[0]


def get_len_prefix_msg(f, pb_type):
    mlen = unmarshal_len(f)
    msg_buf = f.read(mlen)
    msg = pb_type()
    msg.ParseFromString(msg_buf)
    return msg


class FuzzableByteSet:

    # label_set: (uint32 set)   taint labels, i.e. input bytes
    def __init__(self, label_set):
        # this is so that we can hash on it
        self.labels = tuple(label_set)
        self.index = None

    # marshal FuzzableByteSet object to f
    # f should be a file-like object
    def marshal(self, f):
        assert (not (self.index is None))
        msg = taint_analysis_pb2.FuzzableByteSet()
        msg.index = self.index
        msg.label.extend(list(self.labels))
        msg_str =  msg.SerializeToString()
        marshal_len(f, len(msg_str))
        f.write(msg_str)

    def __str__(self):
        return "(Fbs,index=%d,labels=%s)" % (self.index, str(self.labels))


# read a fuzzable byte set out of the file
# and return it as a FuzzableByteSet object
def unmarshal_fuzzable_byte_set(f):    
    msg = get_len_prefix_msg(f, taint_analysis_pb2.FuzzableByteSet)
    fbs = FuzzableByteSet(msg.label)
    fbs.index = msg.index
    return fbs


class InstrType(Enum):
    LD = 1    # load and store 
    ST = 2  
    CMP = 3   # compare 
    BR = 4    # branch
    JI = 4    # indirect jump


class TaintedInstruction:

    # pc:           (uint64)    program counter within module 
    # module:       (string)    module this instruction is in 
    # typ:          InstrType   type of instruction
    def __init__(self, pc, module, typ):
        self.pc = pc
        self.module = module
        self.type = typ
        self.index = None

    # marshal TaintedInstr object to f
    # f must be file-like
    def marshal(self, f):
        assert (not (self.index is None))
        msg = taint_analysis_pb2.TaintedInstruction()
        msg.index = self.index
        msg.pc = self.pc
        msg.module = self.module
        msg.type = str(self.type)
        msg_str = msg.SerializeToString()
        marshal_len(f, len(msg_str))
        f.write(msg_str)

    def __str__(self):
        return "(Ti,index=%d,pc=%x,module=%s,type=%s)" % (self.index,self.pc,self.module,self.type)


def unmarshal_tainted_instruction(f):
    msg = get_len_prefix_msg(f, taint_analysis_pb2.TaintedInstruction)
    ti = TaintedInstruction(msg.pc, msg.module, msg.type)
    ti.index = msg.index
    return ti


class TaintMapping:

    # fbs:                    FuzzableByteSet
    # ti:                     TaintedInstruction 
    # value:        (uint64)  this is the actual internal program value that was tainted  
    # value_length: (uint32)  number of bytes in the tainted value 
    # trace_point:            (float)   where in program trace: 0 is start and 1 is end
    # min_compute_distance:   (uint32)  min compute distance tainted byte in the value
    # max_compute_distance:   (uint32)  max compute distance tainted byte in the value
    def __init__(self, fbs, ti, value, value_length, trace_point,  \
                 min_compute_distance, max_compute_distance):
        self.fbs = fbs
        self.ti = ti
        self.value = value
        self.value_length = value_length
        self.trace_point = trace_point
        self.min_compute_distance = min_compute_distance
        self.max_compute_distance = max_compute_distance
        
    def marshal(self, f):
        msg = taint_analysis_pb2.TaintMapping()
        assert (not (self.fbs.index is None))
        assert (not (self.ti.index is None))
        msg.fuzzable_byte_set = self.fbs.index
        msg.tainted_instruction = self.ti.index
        msg.value = self.value
        msg.value_length = self.value_length
        msg.trace_point = self.trace_point
        msg.min_compute_distance = self.min_compute_distance
        msg.max_compute_distance = self.max_compute_distance
        msg_str = msg.SerializeToString()
        marshal_len(f, len(msg_str))
        f.write(msg_str)

    def __str__(self):
        return "(Tm,fbs=%s,ti=%s,value=%d,value_length=%d,trace_point=%f,compute_distance(%d,%d))" % \
                (str(self.fbs),str(self.ti),self.value,self.value_length,self.trace_point, \
                 self.min_compute_distance,self.max_compute_distance)

# hmm.  this doesn't exactly work
# unless we have fbsi and tii (index -> thing)
def unmarshal_taint_mapping(f, fbsi, tii):
    msg = get_len_prefix_msg(f, taint_analysis_pb2.TaintMapping)    
    tm = TaintMapping(fbsi[msg.fuzzable_byte_set], tii[msg.tainted_instruction], \
                      msg.value, msg.value_length, msg.trace_point, \
                      msg.min_compute_distance, msg.max_compute_distance)
    return tm



class TaintAnalysis:

    def __init__(self, protobuf=None):
        # array of fuzzable byte sets
        self.fbsa = []
        # map from labels in fuzzable byte set to index into fbsa
        self.fbsi = {}
        # array of tainted instructions
        self.tia = []
        # map from tainted instr to index into tia
        self.tii = {}
        # taint mappings
        self.tma = []
        if not (protobuf is None):
            self.from_protobuf(protobuf)
            return
        
    # Add a fuzzable byte set
    # fbs must be a FuzzableByteSet
    def add_fuzzable_byte_set(self, fbs):
        if not (fbs in self.fbsi):
            fbs.index = len(self.fbsa)
            self.fbsa.append(fbs)
            self.fbsi[fbs] = fbs.index

    # Add a tainted instruction
    # ti must be a TaintedInstruction
    def add_tainted_instruction(self, ti):
        if not (ti in self.tii):
            ti.index = len(self.tia)
            self.tia.append(ti)
            self.tii[ti] = ti.index

    # Add a taint mapping between a fuzzable byte set and a tainted instruction
    # tm must be a TaintMapping
    def add_taint_mapping(self, tm):
        # get indices for fbs and ti
        self.add_fuzzable_byte_set(tm.fbs)
        self.add_tainted_instruction(tm.ti)
        i_fbs = self.fbsi[tm.fbs]
        i_ti = self.tii[tm.ti]
        # add mapping to list of mappings
#        mapping = (i_fbs, i_ti, tm.trace_point, tm.min_compute_distance, tm.max_compute_distance)
        self.tma.append(tm)


    # Generate protobuf for tainta analysis in this object
    def marshal(self, f):
        # first the fuzzable byte sets
        marshal_len(f, len(self.fbsa))
        for fbs in self.fbsa:
            fbs.marshal(f)
        # now the tainted instructions
        marshal_len(f, len(self.tia))
        for ti in self.tia:
            ti.marshal(f)
        # now the mappings
        marshal_len(f, len(self.tma))
        for tm in self.tma:
            tm.marshal(f)

    def __str__(self):
        buf = ""
        for tm in self.tma:
            buf += str(tm) + "\n"
        return buf
            


def unmarshal_taint_analysis(f):
    ta = TaintAnalysis()
    l = unmarshal_len(f)
    i = 1
    while i <= l:
        fbs = unmarshal_fuzzable_byte_set(f)
        ta.add_fuzzable_byte_set(fbs)
        i += 1
    l = unmarshal_len(f)
    while i <= 1:
        ti = unmarshal_tainted_instruction(f)
        ta.add_tainted_instruction(ti)
        i += 1
    l = unmarshal_len(f)
    while i <= 1:
        tm = unmarshal_taint_mapping(f, ta.fbsi, ta.tia)
        ta.add_taint_mapping(tm)
    return ta
