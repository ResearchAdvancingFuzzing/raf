
"""
A very simple in-memory and pickle-based knowledge store


"""

import os
import sys
import queue

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
            return md5(inp.read())


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
        return md5(str(tinstr.address.offset) + str(tinstr.address.module.uuid) + str(tinstr.type) \
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
        uuid_data = str(edge.hit_count)
        for a in edge.address:
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
        print(experiment.target.source_hash)
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
        self.taint_inputs = set([])
        self.instr2tainted_inputs = {}
        self.inp2fuzzable_byte_sets = {}
        self.inp2tainted_instructions = {}
        self.modules = ModulePickle()
        self.addresses = AddressPickle()
        self.edges = EdgeCoveragePickle()
        self.corpora = CorpusPickle() 
        self.experiments = ExperimentPickle()
        self.executions = ExecutionPickle() 
        self.inp2edge_coverage = {}
        #self.edge_coverage = EdgeCoveragePickle() 

    def execution_exists(self, execution): 
        return self.executions.exists(execution)

    def add_execution(self, execution): 
        if self.execution_exists(execution): 
            was_new = 0
            ex = self.get_execution(execution)
        else: 
            (was_new, ex) = self.executions.add(execution) 
            self.execution_inputs.add(ex.input.uuid) 
        return (was_new, ex)

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
        attrs = [attr for attr in dir(old) if not (attr[0].startswith('__') and attr[0].endswith('__'))] 
        for attr in attrs: 
            if hasattr(new, attr) and getattr(new, attr) == True and \
                    hasattr(old, attr) and getattr(old, attr) == False: 
                setattr(old, attr, getattr(new, attr)) 

    def add_input(self, input):
        # We need to update the fields that aren't present if there are any 
        if self.input_exists(input): 
            was_new = 0
            kb_input = self.get_input(input) 
            self.update_input(kb_input, input)
        #else:
        #    (was_new, kb_input) = self.inputs.add(input)
        #    self.inputs_without_coverage.add(kb_input.uuid) 
        #return (was_new, kb_input) 
        return self.inputs.add(input) 

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
        return self.tainted_instructions.add(tinstr)
    
    def get_tainted_instruction(self, tinstr):
        return self.tainted_instructions.get(tinstr)

    def taint_mapping_exists(self, taintm):
        return self.taint_mappings.exists(taintm)

    def add_taint_mapping(self, taintm):
        if self.taint_mapping_exists(taintm):
           tm = self.get_taint_mapping(taintm)
           was_new = 0
        else:
            # keep track of set of inputs that we've taint analyzed
            #taint_uuid = # something 
            was_new = 1
            input_uuid = taintm.input.uuid # nothing else set right now
            instr_uuid = taintm.tainted_instruction.uuid
            fbs_uuid = taintm.fuzzable_byte_set.uuid 
            tm = self.taint_inputs.add(input_uuid)#i.ti.uuid)
            # keep track, by instruction, of what inputs taint it
            if not (input_uuid in self.instr2tainted_inputs):
                self.instr2tainted_inputs[instr_uuid] = set([])
            self.instr2tainted_inputs[instr_uuid].add(input_uuid)
            if not (input_uuid in self.inp2fuzzable_byte_sets):
                self.inp2fuzzable_byte_sets[input_uuid] = set([])
            self.inp2fuzzable_byte_sets[input_uuid].add(fbs_uuid)
            if not (input_uuid in self.inp2tainted_instructions):
                self.inp2tainted_instructions[input_uuid] = set([])
            self.inp2tainted_instructions[input_uuid].add(instr_uuid)
        return (was_new, tm)
    
    def get_taint_mapping(self, taintm):
        return self.taint_mappings.get(taintm)

    def add_address(self, address):
        return self.addresses.add(address)
    
    def add_edge_coverage(self, edge):
        #print("In edge coverage", flush=True) 
        uuid = self.inputs.hash(edge.input) 
        #print(uuid, flush=True) 
        inp = self.inputs.get_by_id(uuid)
        #print(inp, flush=True)
        if not inp.uuid in self.inp2edge_coverage:
            self.inp2edge_coverage[inp.uuid] = []
            self.inputs_without_coverage.remove(inp.uuid) 
        self.inp2edge_coverage[inp.uuid].append(edge) 
        #print("Leaving edge coverage", flush=True) 
        return self.edges.add(edge)

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
        return self.instr2tainted_inputs[instr.uuid]
                
    def get_fuzzable_byte_sets_for_taint_input(self, inp):
        if not inp.uuid in self.inp2fuzzable_byte_sets:
            return None
        return self.inp2fuzzable_byte_sets[inp.uuid]

    def get_tainted_instructions_for_taint_input(self, inp):
        if not inp.uuid in self.inp2tainted_instructions:
            return None
        return self.inp2tainted_instructions[inp.uuid]

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
        return [self.inputs.get_by_id(uuid) for uuid in inp_set] 

    def get_taint_inputs(self):
        return self.get_input_set("taint_analyzed", 1) 

    def get_execution_inputs(self):
        return self.get_input_set("fuzzed", 1) 

    def get_inputs_with_coverage(self):
        return self.get_input_set("coverage_complete", 1) 

    def get_inputs_without_coverage(self):
        coverage_set = self.get_input_set("coverage_complete", 0) 
        inc_coverage_set = self.get_input_set("increased_coverage", 1)
        return inc_coverage_set - coverage_set

    def get_seed_inputs(self): 
        return self.get_input_set("seed", 1) 

    def get_input_by_id(self, uuid): 
        return self.inputs.get_by_id(uuid) 
