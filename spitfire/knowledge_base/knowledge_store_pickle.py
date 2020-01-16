
"""
A very simple in-memory and pickle-based knowledge store


"""

import os
import sys


# walk up the path to find 'spitfire' and add that to python path
# at most 10 levels up?
p = os.path.abspath(__file__)
for i in range(10):
    (hd, tl) = os.path.split(p)
    if tl == "spitfire":
        sys.path.append(p)
        sys.path.append(hd)
        break
    p = hd


from knowledge_store import KnowledgeStore

import hashlib

def md5(strToMd5):
    encrptedMd5 = ""
    md5Instance = hashlib.md5()
    bytesToMd5 = bytes(strToMd5, "UTF-8")
    md5Instance.update(bytesToMd5)
    encrptedMd5 = md5Instance.hexdigest()
    return bytes(encrptedMd5, "UTF-8")


class TargetNotFound(Exception):

    def __init__(self, target):
        self.target = target

    def __str__(self):
        return "Target not found exception name=%s filepath=%s" \
            % (target.name, target.filepath) 


class InputNotFound(Exception):

    def __init__(self, inp):
        self.inp = inp

    def __str__(self):
        return "Input not found exception filepath=%s" % inp.filepath 



class ThingPickle:

    def __init__(self, name):
        self.things = {}
        self.name = name

    def pickle(self):
        with open(self.name, "w") as f:
            pickle.dump(f, self.things)

    def unpickle(self):
        with open(self.name, "r") as f:
            self.things = pickle.load(f)
    
    def check(self, thing):
        raise NotImplementedError

    def hash(self, thing):
        raise NotImplementedError

    def find(self, thing):
        thing_uuid = self.hash(thing)
        if thing_uuid in self.things:
            return (self.things[thing_uuid], thing_uuid)
        return (None, thing_uuid)
        
    def exists(self, thing):
#        print(" exists? " + (str(thing)))
        self.check(thing)
        (th, th_uuid) = self.find(thing)
#        if th is None:
#            print (" .. no")
#        else:
#            print (" .. yes")
        return (not (th is None))

    def add(self, thing):
#        print(" add " + (str(thing)))
        self.check(thing)
        (th, th_uuid) = self.find(thing)
#        print ("uuid = %s" % (str(th_uuid)))
        if th is None:
            thing.uuid = th_uuid
            self.things[th_uuid] = thing
            return (True, thing)
        return (False, th)

    def get(self, thing):
        self.check(thing)
        (th, th_uuid) = self.find(thing)
        if th is None:
            raise ThingNotFound(str(thing))
        return th


class TargetPickle(ThingPickle):

    def __init__(self):
        super().__init__("target")
    
    def check(self, thing):
        assert hasattr(thing,"name")
        assert hasattr(thing,"filepath")
        assert hasattr(thing,"source_hash")

    def hash(self, thing):
        return md5(thing.name + thing.filepath + thing.source_hash)


class InputPickle(ThingPickle):

    def __init__(self):
        super().__init__("inputs")
    
    def check(self, inp):
        assert(hasattr(inp,"filepath"))

    def hash(self, inp):
        return md5(inp.filepath)


class AnalysisToolPickle(ThingPickle):

    def __init__(self):
        super().__init__("analysistool")
        
    def check(self, te):
        assert hasattr(te,"name")
        assert hasattr(te,"source_string")

    def hash(self, te):
        return md5(te.name + te.source_string)


class TaintAnalysisPickle(ThingPickle):

    def __init__(self):
        super().__init__("taintanalyses")
        
    def check(self, ta):
        assert hasattr(ta, "taint_engine")
        assert hasattr(ta, "target")
        assert hasattr(ta, "input")

    def hash(self, ta):
        return md5(str(ta.taint_engine.uuid) + \
                   str(ta.program) + \
                   str(ta.input))


class FuzzableByteSetPickle(ThingPickle):

    def __init__(self):
        super().__init__("fuzzablebytesets")
    
    def check(self, fbs):
        assert hasattr(fbs, "label")
        
    def hash(self, fbs):
        return md5(str(fbs.label))


class TaintedInstructionPickle(ThingPickle):
    
    def __init__(self):
        super().__init__("taintedinstructions")
    
    def check(self, tinstr):
        assert hasattr(tinstr, "address")
        assert hasattr(tinstr, "type")
        assert hasattr(tinstr, "instruction_bytes")

    def hash(self, tinstr):
        return md5(str(tinstr.address.offset) + str(tinstr.address.module.uuid) + tinstr.module + str(tinstr.type) \
                   + str(tinstr.instruction_bytes))


class TaintMappingPickle(ThingPickle):

    def __init__(self):
        super().__init__("taintmappings")
    
    def check(self, taintm):
        assert hasattr(taintm, "input")
        assert hasattr(taintm, "fuzzable_byte_set")
        assert hasattr(taintm, "tainted_instruction")
        assert hasattr(taintm, "value")
        assert hasattr(taintm, "value_length")
        assert hasattr(taintm, "instruction_count")
        assert hasattr(taintm, "min_compute_distance")
        assert hasattr(taintm, "max_compute_distance")

    def hash(self, taintm):
        return  md5(str(taintm.input.uuid) + str(taintm.fuzzable_byte_set.uuid) \
                    + str(taintm.tainted_instruction.uuid) + str(taintm.value) \
                    + str(taintm.value_length) + str(taintm.instruction_count) \
                    + str(taintm.min_compute_distance) \
                    + str(taintm.max_compute_distance)) 

class ModulePickle(ThingPickle):
    def __init__(self):
        super().__init__("module")

    def check(self, module):
        assert hasattr(module, "base")
        assert hasattr(module, "end")

    def hash(self, module):
        return md5(str(module.base) + str(module.end))
        
class AddressPickle(ThingPickle):
    def __init__(self):
        super().__init__("address")

    def check(self, address):
        assert hasattr(address, "module")
        assert hasattr(address, "offset")

    def hash(self, address):
        return md5(str(address.module.uuid) + str(address.offset))

class EdgeCoveragePickle(ThingPickle):
    def __init__(self):
        super().__init__("edgecoverage")

    def check(self, edge):
        assert hasattr(edge, "hit_count")
        assert hasattr(edge, "address")
        assert hasattr(edge, "input")

    def hash(self, edge):
        return md5(str(edge.hit_count) + str(edge.address.uuid) + str(edge.input.uuid))

class KnowledgeStorePickle(KnowledgeStore):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.config = ksc
        self.target = TargetPickle()
        self.inputs = InputPickle()
        self.analysis_tool = AnalysisToolPickle()
        self.taint_analyses = TaintAnalysisPickle()
        self.fuzzable_byte_sets = FuzzableByteSetPickle()
        self.tainted_instructions = TaintedInstructionPickle()
        self.taint_mappings = TaintMappingPickle()
        self.taint_inputs = set([])
        self.instr2tainted_inputs = {}
        self.inp2fuzzable_byte_sets = {}
        self.inp2tainted_instructions = {}
        self.modules = ModulePickle()
        self.addresses = AddressPickle()
        self.edges = EdgeCoveragePickle()
        
    def target_exists(self, target):
        return self.target.exists(target)

    def add_target(self, target):
        return self.target.add(target)
    
    def get_target(self, target):
        return self.target.get(target)


    def input_exists(self, input):
        return self.inputs.exists(input)

    def add_input(self, input):
        return self.inputs.add(input)
    
    def get_input(self, input):
        return self.inputs.get(input)

    
    def analysis_tool_exists(self, tool):
        return self.analysis_tool.exists(tool)

    def add_analysis_tool(self, tool):
        return self.analysis_tool.add(tool)
    
    def get_analysis_tool(self, tool):
        return self.analysis_tool.get(tool)

   
    def taint_analysis_exists(self, taint_analysis):
        return self.taint_analyses.exists(taint_analysis)

    def add_taint_analysis(self, taint_analysis):
        return self.taint_analyses.add(taint_analysis)
    
    def get_taint_analysis(self, taint_analysis):
        return self.taint_analyses.get(taint_analysis)


    def fuzzable_byte_set_exists(self, fbs):
        return self.fuzzable_byte_sets.exists(fbs)

    def add_fuzzable_byte_set(self, fbs):
        return self.fuzzable_byte_sets.add(fbs)
    
    def get_fuzzable_byte_set(self, fbs):
        return self.fuzzable_byte_sets.get(fbs)

    
    def tainted_instruction_exists(self, tinstr):
        return self.tainted_instructions.exists(tinstr)

    def add_tainted_instruction(self, tinstr):
        return self.tainted_instructions.add(tinstr)
    
    def get_tainted_instruction(self, tinstr):
        return self.tainted_instructions.get(tinstr)

    def taint_mapping_exists(self, taintm):
        return self.taint_mappings.exists(taintm)

    def add_taint_mapping(self, taintm):
        if self.taint_mapping_exists(taintm):
           tm = self.get_taint_mapping(taintm)
        else:
            # keep track of set of inputs that we've taint analyzed
            tm = self.taint_inputs.add(tm.inp_uuid)
            # keep track, by instruction, of what inputs taint it
            if not (tm.ti_uuid in self.instr2tainted_inputs):
                self.instr2tainted_inputs[tm.ti_uuid] = set([])
            self.instr2tainted_inputs[tm.ti_uuid].add(tm.inp_uuid)
            if not (tm.inp_uuid in self.inp2fuzzable_byte_sets):
                self.inp2fuzzable_byte_sets[tm.inp_uuid] = set([])
            self.inp2fuzzable_byte_sets[tm.inp_uuid].add(tm.fbs_uuid)
            if not (tm.inp_uuid in self.inp2tainted_instructions):
                self.inp2tainted_instructions[tm.inp_uuid] = set([])
            self.inp2tainted_instructions.add(tm.ti.uuid)
        return tm
    
    def get_taint_mapping(self, taintm):
        return self.taint_mappings.get(taintm)

    def add_address(self, address):
        return self.addresses.add(address)

    def add_edge_coverage(self, edge):
        return self.edges.add(edge)

    def add_module(self, module):
        return self.modules.add(module)

    # XXX 
    # Corpus & Experiment not yet implemented 

    def corpus_exists(self, corp):
        raise NotImplemented

    def get_corpus(self, corp):
        raise NotImplemented

    def add_corpus(self, corp):
        raise NotImplemented

    def experiment_exists(self, experiment):
        raise NotImplemented

    def get_experiment(self, experiment):
        raise NotImplemented

    def add_experiment(self, experiment):
        raise NotImplemented


    def get_tainted_instructions(self):
        return self.tainted_instructions
        
    def get_taint_inputs(self):
        return self.taint_inputs

    def get_taint_inputs_for_tainted_instruction(self, instr):
        if not instr.uuid in self.instr2tainted_inputs:
            return None # is this how we have a generator with no elements?
        return self.instr2tainted_inputs[instr.uuid]
                
    def get_fuzzable_byte_sets_for_taint_input(self, inp):
        if not inp.uuid in self.inp2fuzzable_byte_sets:
            return None
        return self.inp2fuzzable_byte_sets[inp.uuid]

    def get_tainted_instructions_for_taint_input(self, inp):
        if not inp.uuid in self.inp2tainted_instructions:
            return None
        return self.inp2tainted_instructions[inp.uuid]
