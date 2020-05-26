
"""
A very simple in-memory and pickle-based knowledge store


"""

import os
import sys
import queue
from enum import Enum

class Mode(Enum):
    RUNNING = 1
    PAUSED = 2
        

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
    if isinstance(strToMd5, str):
        bytesToMd5 = bytes(strToMd5, "UTF-8")
    else: # bytes
        bytesToMd5 = strToMd5
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

    def get_by_id (self, uuid): 
        if uuid in self.things: 
            return (self.things[uuid]) 
        return None

    def find(self, thing):
        thing_uuid = self.hash(thing)
        if thing_uuid in self.things:
            return (self.things[thing_uuid], thing_uuid)
        return (None, thing_uuid)
        
    def exists(self, thing):
        self.check(thing)
        (th, th_uuid) = self.find(thing)
        return (not (th is None))

    def add(self, thing):
        self.check(thing)
        (th, th_uuid) = self.find(thing)
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
        assert hasattr(thing,"source_hash")

    def hash(self, thing):
        return md5(thing.name + thing.source_hash)


class InputPickle(ThingPickle):

    def __init__(self):
        super().__init__("inputs")
    
    def check(self, inp):
        assert(hasattr(inp,"filepath"))

    def hash(self, inp):
        with open(inp.filepath, 'rb') as inp:
            f = inp.read() 
            return md5(f)


class AnalysisToolPickle(ThingPickle):

    def __init__(self):
        super().__init__("analysistool")
        
    def check(self, te):
        assert hasattr(te,"name")
        assert hasattr(te,"source_string")

    def hash(self, te):
        return md5(te.name + te.source_string)


class AnalysisPickle(ThingPickle):

    def __init__(self):
        super().__init__("analyses")
        
    def check(self, ta):
        assert hasattr(ta, "tool")
        assert hasattr(ta, "target")
        assert hasattr(ta, "input")

    def hash(self, ta):
        # NB: each of these is a uuid
        return md5(str(ta.tool) + \
                   str(ta.target) + \
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
        return md5(str(tinstr.address.uuid) + str(tinstr.type) + str(tinstr.instruction_bytes))
        #return md5(str(tinstr.address.offset) + str(tinstr.address.module.uuid) + str(tinstr.type) \
        #           + str(tinstr.instruction_bytes))


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
        assert address.module.uuid != ""
        assert hasattr(address, "offset")
        
    def hash(self, address):
        return md5(str(address.module.uuid) + str(address.offset))
'''
class EdgeCoveragePickle(ThingPickle):
    def __init__(self):
        super().__init__("edgecoverage")

    def check(self, edge):
        assert hasattr(edge, "hit_count")
        assert hasattr(edge, "address")
        assert hasattr(edge, "input")

    def hash(self, edge):
        uuid_data = "" # str(edge.hit_count)
        print("addresses:", flush=True)
        for a in edge.address:
            print(str(a), flush=True)
            uuid_data += str(a.uuid)
        uuid_data += str(edge.input.uuid)
        
        return md5(uuid_data)
'''

class CorpusPickle(ThingPickle): 
    def __init__(self): 
        super().__init__("corpus")

    def check(self, corpus): 
        assert hasattr(corpus, "name")
        assert hasattr(corpus, "input") 
        
    def hash(self, corpus): 
        uuid = []
        for seed in corpus.input: 
            uuid.append(seed.uuid) 
        uuid = b"".join(uuid)
        return md5(str(uuid))

class ExperimentPickle(ThingPickle): 
    def __init__(self):
        super().__init__("experiment")

    def check(self, experiment):
        assert hasattr(experiment, "target")
        assert hasattr(experiment, "seed_corpus")

    def hash(self, experiment):
        #print(experiment.target.source_hash)
        target_hash = experiment.target.source_hash
        return md5(str(experiment.seed_corpus.uuid) + target_hash)

class ExecutionPickle(ThingPickle):
    def __init__(self):
        super().__init__("execution")

    def check(self, execution):
        assert hasattr(execution, "target")
        assert hasattr(execution, "input")

    def hash(self, execution):
        return md5(str(execution.input.uuid) + str(execution.target.uuid))


class EdgeCoveragePickle(ThingPickle): 
    def __init__(self):
        super().__init__("edge_coverage")

    def check(self, ec): 
        assert hasattr(ec, "hit_count")
        assert hasattr(ec, "address")
        assert hasattr(ec, "input")
    
    def hash(self, ec): 
        uuid = []
        for address in ec.address:
            uuid.append(address.uuid) 
        uuid = b"".join(uuid)
        return md5(str(uuid))


class KnowledgeStorePickle(KnowledgeStore):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.config = ksc
        self.target = TargetPickle()
        self.inputs = InputPickle()
        self.analysis_tool = AnalysisToolPickle()
        self.analyses = AnalysisPickle()
        self.fuzzable_byte_sets = FuzzableByteSetPickle()
        self.tainted_instructions = TaintedInstructionPickle()
        self.taint_mappings = TaintMappingPickle()
        #self.taint_inputs = set([])
        self.instr2tainted_inputs = {}
        self.inp2fuzzable_byte_sets = {}
        self.inp2tainted_instructions = {}
        self.fbs2taint_mappings = {}
        self.modules = ModulePickle()
        self.addresses = AddressPickle()
        self.edges = EdgeCoveragePickle()
        self.corpora = CorpusPickle() 
        self.experiments = ExperimentPickle()
        self.executions = ExecutionPickle() 
        self.inp2edge_coverage = {}
        #self.edge_coverage = EdgeCoveragePickle() 
        self.mode = Mode.RUNNING
        
        
    def pause(self):
        self.mode = Mode.PAUSED
        return true

    def continue(self):
        self.mode = Mode.RUNNING
        return true
        
    def execution_exists(self, execution): 
        return self.executions.exists(execution)

    def add_execution(self, execution): 
        return self.executions.add(execution) #(was_new, ex)

    def get_execution(self, execution):
        return self.executions.get(execution) 

    def target_exists(self, target):
        return self.target.exists(target)

    def add_target(self, target):
        return self.target.add(target)
    
    def get_target(self, target):
        return self.target.get(target)


    def input_exists(self, input):
        return self.inputs.exists(input)

    def update_input(self, old, new):
        updated = False
        attrs = [attr for attr in dir(old) if not (attr[0].startswith('__') and attr[0].endswith('__'))] 
        for attr in attrs: 
            if hasattr(new, attr) and getattr(new, attr) == True and \
                    hasattr(old, attr) and getattr(old, attr) == False: 
                setattr(old, attr, getattr(new, attr)) 
                updated = True
        return updated 

    def add_input(self, input):
        # We need to update the fields that aren't present if there are any 
        updated = False 
        if self.input_exists(input):
            kb_input = self.get_input(input) 
            updated = self.update_input(kb_input, input)
        (was_new, inp) = self.inputs.add(input)
        if updated:
            was_new = 1
        return (was_new, inp) 

    def get_input(self, input):
        return self.inputs.get(input)

    
    def analysis_tool_exists(self, tool):
        return self.analysis_tool.exists(tool)

    def add_analysis_tool(self, tool):
        return self.analysis_tool.add(tool)
    
    def get_analysis_tool(self, tool):
        return self.analysis_tool.get(tool)

   
    def analysis_exists(self, analysis):
        return self.analyses.exists(analysis)

    def add_analysis(self, analysis):
        return self.analyses.add(analysis)
    
    def get_analysis(self, analysis):
        return self.analyses.get(analysis)


    def fuzzable_byte_set_exists(self, fbs):
        return self.fuzzable_byte_sets.exists(fbs)

    def add_fuzzable_byte_set(self, fbs):
        return self.fuzzable_byte_sets.add(fbs)
    
    def get_fuzzable_byte_set(self, fbs):
        return self.fuzzable_byte_sets.get(fbs)
    
    def tainted_instruction_exists(self, tinstr):
        return self.tainted_instructions.exists(tinstr)

    def add_tainted_instruction(self, tinstr):
        #(was_new, ti) = self.tainted_instructions.add(tinstr)
        #if was_new: 
        #    print("New: %s" % str(ti.uuid))
        #else:
        #    print("Old: %s" % str(ti.uuid))
        return self.tainted_instructions.add(tinstr)
    
    def get_tainted_instruction(self, tinstr):
        return self.tainted_instructions.get(tinstr)

    def taint_mapping_exists(self, taintm):
        return self.taint_mappings.exists(taintm)

    def add_taint_mapping(self, taintm):
        (was_new, kb_tm) = self.taint_mappings.add(taintm)
        if was_new: #not self.taint_mapping_exists(taintm):
           #tm = self.get_taint_mapping(taintm)
           #was_new = 0
        #else:
            # keep track of set of inputs that we've taint analyzed
            #taint_uuid = # something 
            #was_new = 1
            input_uuid = taintm.input.uuid # nothing else set right now
            instr_uuid = taintm.tainted_instruction.uuid
            fbs_uuid = taintm.fuzzable_byte_set.uuid 
            #tm = self.taint_inputs.add(input_uuid)#i.ti.uuid)
            # keep track, by instruction, of what inputs taint it
            if not (fbs_uuid in self.fbs2taint_mappings): 
                self.fbs2taint_mappings[fbs_uuid] = set([])
            self.fbs2taint_mappings[fbs_uuid].add(kb_tm.uuid)
            if not (instr_uuid in self.instr2tainted_inputs):
                self.instr2tainted_inputs[instr_uuid] = set([])
            self.instr2tainted_inputs[instr_uuid].add(input_uuid)
            if not (input_uuid in self.inp2fuzzable_byte_sets):
                self.inp2fuzzable_byte_sets[input_uuid] = set([])
            self.inp2fuzzable_byte_sets[input_uuid].add(fbs_uuid)
            if not (input_uuid in self.inp2tainted_instructions):
                self.inp2tainted_instructions[input_uuid] = set([])
            self.inp2tainted_instructions[input_uuid].add(instr_uuid)
        return (was_new, kb_tm) #self.taint_mappings.add(taintm) #(was_new, tm)
    
    def get_taint_mapping(self, taintm):
        return self.taint_mappings.get(taintm)

    def add_address(self, address):
        return self.addresses.add(address)
    
    def add_edge_coverage(self, edge):
        (was_new, e) = self.edges.add(edge) 
        if was_new:
            inp_uuid = edge.input.uuid
            if not inp_uuid in self.inp2edge_coverage: 
                self.inp2edge_coverage[inp_uuid] = []
            self.inp2edge_coverage[inp_uuid].append(e)
        return (was_new, e)  

    def add_module(self, module):
        return self.modules.add(module)

    # XXX 
    # Corpus & Experiment not yet implemented 
    
    def corpus_exists(self, corp):
        return self.corpora.exists(corp)
        #raise NotImplemented

    def get_corpus(self, corp):
        return self.corpora.get(corp)
        #raise NotImplemented

    def add_corpus(self, corp):
        return self.corpora.add(corp)
        #raise NotImplemented

    def experiment_exists(self, experiment):
        return self.experiments.exists(experiment)
        #raise NotImplemented

    def get_experiment(self, experiment):
        return self.experiments.get(experiment)
        #raise NotImplemented

    def add_experiment(self, experiment):
        return self.experiments.add(experiment)
        #raise NotImplemented

    def get_tainted_instructions(self):
        return self.tainted_instructions
        
    def get_taint_inputs_for_tainted_instruction(self, instr):
        if not instr.uuid in self.instr2tainted_inputs:
            return None # is this how we have a generator with no elements?
        return [self.inputs.get_by_id(inp_id) for inp_id in self.instr2tainted_inputs[instr.uuid]]
                
    def get_fuzzable_byte_sets_for_taint_input(self, inp):
        if not inp.uuid in self.inp2fuzzable_byte_sets:
            return None
        return [self.fuzzable_byte_sets.get_by_id(fbs_id) for fbs_id in self.inp2fuzzable_byte_sets[inp.uuid]]
        #print(thing)

    def get_tainted_instructions_for_taint_input(self, inp):
        if not inp.uuid in self.inp2tainted_instructions:
            return None
        return [self.tainted_instructions.get_by_id(ti_id) for ti_id in self.inp2tainted_instructions[inp.uuid]]

    def get_taint_mappings_for_fuzzable_byte_set(self, fbs): 
        if not fbs.uuid in self.fbs2taint_mappings: 
            return None
        return [self.taint_mappings.get_by_id(tm_id) for tm_id in self.fbs2taint_mappings[fbs.uuid]]

    def get_edge_coverage_for_input(self, inp):
        if not inp.uuid in self.inp2edge_coverage:
            return None
        return self.inp2edge_coverage[inp.uuid]


    # All the functions that need to iterate through inputs to get their results 
    def get_input_set(self, attrib, value): 
        inp_set = set([]) 
        for inp_id in self.inputs.things: 
            inp = self.inputs.get_by_id(inp_id) 
            if hasattr(inp, attrib) and getattr(inp, attrib) == value:
               inp_set.add(inp_id) 
               #inp_set.add(inp)
        #return {self.inputs.get_by_id(uuid) for uuid in inp_set} 
        return inp_set

    def get_taint_inputs(self):
        return [self.inputs.get_by_id(uuid) for uuid in self.get_input_set("taint_analyzed", 1)] 

    def get_execution_inputs(self):
        return [self.inputs.get_by_id(uuid) for uuid in self.get_input_set("fuzzed", 1)] 


    def get_inputs_with_coverage(self):
        return [self.inputs.get_by_id(uuid) for uuid in self.get_input_set("coverage_complete", 1)] 
        #return self.get_input_set("coverage_complete", 1) 

    def get_inputs_without_coverage(self):
        coverage_set = self.get_input_set("coverage_complete", 1) 
        inc_coverage_set = self.get_input_set("increased_coverage", 1)
        new = inc_coverage_set - coverage_set
        return [self.inputs.get_by_id(uuid) for uuid in new] 
        #return inc_coverage_set - coverage_set

    def get_seed_inputs(self): 
        #return self.get_input_set("seed", 1) 
        return [self.inputs.get_by_id(uuid) for uuid in self.get_input_set("seed", 1)] 

    def get_input_by_id(self, inp):
        assert hasattr (inp, "uuid")
        return self.inputs.get_by_id(inp.uuid)



