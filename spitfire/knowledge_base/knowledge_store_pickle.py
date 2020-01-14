
"""
A very simple in-memory and pickle-based knowledge store

>>> import md5
>>> m = md5.new()
>>> m.update("Nobody inspects")
>>> m.update(" the spammish repetition")
>>> m.digest()


"""

import md5



class ProgramNotFound(Exception):

    def __init__(self, prog):
        self.prog = prog

    def __str__(self):
        return "Program not found exception name=%s filepath=%s" \
            % (prog.name, prog.filepath) 


class InputNotFound(Exception):

    def __init__(self, inp):
        self.inp = inp

    def __str__(self):
        return "Input not found exception filepath=%s" % inp.filepath 



class ThingPickle:

    def __init__(self):
        self.things = {}
    
    def __check(self, thing):
        pass

    def __hash(self, thing):
        pass

    def __find(self, thing):
        thing_uuid = self.__hash(thing)
        if thing_uuid in self.thing:
            return (self.things[thing_uuid], thing_uuid)
        return (None, thing_uuid)
        
    def exists(self, thing):
        self.__check(thing)
        (th, th_uuid) = self.__find(thing)
        return (not (th is None))

    def add(self, thing):
        self.__check(thing)
        (th, th_uuid) = self.__find(thing)
        if th is None:
            thing.uuid = th_uuid
            self.things[th_uuid] = thing
            return thing
        return th

    def get(self, thing):
        self.__check(thing)
        (th, th_uuid) = self.__find(thing)
        if th is None:
            raise ThingNotFound(str(thing))
        return th


class ProgramPickle(ThingPickle):
    
    def __check(self, program):
        assert hasattr(program,"name")
        assert hasattr(program,"filepath")
        assert hasattr(program,"git_hash")

    def __hash(self, program):
        return md5.new(program.name + program.filepath + program.git_hash)


class InputPickle(ThingPickle):

    def __check(self, inp):
        assert(hasattr(inp,"filename"))

    def __hash(self, inp):
        return md5.new(inp.filepath)


class TaintEnginePickle(ThingPickle):
    
    def __check(self, te):
        assert hasattr(taint_engine,"name")
        assert hasattr(taint_engine,"install_string")

    def __hash(self, te):
        return md5.new(te.name + te.clone_string)


class TaintAnalysisPickle(ThingPickle):
    
    def __check(self, ta):
        assert hasattr(taint_analysis, "taint_engine")
        assert hasattr(taint_analysis, "program")
        assert hasattr(taint_analysis, "input")

    def __hash(self, ta):
        return md5.new(taint_analysis.taint_engine + \
                       taint_analysis.program + \
                       taint_analysis.input)


class FuzzableByteSetPickle(ThingPickle):

    def __check(self, fbs):
        assert hasattr(fuzzbs, "label")
        
    def __hash(self, fbs):
        return md5.new(str(fbs.label))


class TaintedInstructionPickle(ThingPickle):
    
    def __check(self, tinstr):
        assert hasattr(tinstr, "pc")
        assert hasattr(tinstr, "module")
        assert hasattr(tinstr, "type")
        assert hasattr(tinstr, "instr_bytes")

    def __hash(self, tinstr):
        return md5.new(str(tinstr.pc) + tinstr.module + str(tinstr.type) \
                       + tinstr.instr_bytes)


class TaintMappingPickle(ThingPickle):

    def __check(self, taintm):
        assert hasattr(taintm, "inp_uuid")
        assert hasattr(taintm, "fbs_uuid")
        assert hasattr(taintm, "ti_uuid")
        assert hasattr(taintm, "value")
        assert hasattr(taintm, "value_length")
        assert hasattr(taintm, "trace_point")
        assert hasattr(taintm, "min_compute_distance")
        assert hasattr(taintm, "max_compute_distance")

    def __hash(self, taintm):
        return  md5.new(str(taintm.inp_uuid) + str(taintm.fbs_uuid) \
                        + str(taintm.ti_uuid) + str(taintm.value) \
                        + str(taintm.value_length) + str(taintm.trace_point) \
                        + str(taintm.min_compute_distance) \
                        + str(taintm.max_compute_distance)) 
    

class KnowledgeStorePickle(KnowledgeStore):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.config = ksc
        self.programs = ProgramPickle()
        self.inputs = InputPickle()
        self.taint_engines = TaintEnginePickle()
        self.taint_analyses = TaintAnalyisPickle()
        self.fuzzable_byte_sets = FuzzableByteSetPickle()
        self.tainted_instructions = TaintedInstructionPickle()
        self.taint_mappings = TaintMappingPickle()
        self.taint_inputs = set([])
        self.instr2tainted_inputs = {}
        self.inp2fuzzable_byte_sets = {}
        self.inp2tainted_instructions = {}

    def program_exists(self, program):
        return self.programs.exists(program)

    def add_program(self, program):
        return self.programs.add(program)
    
    def get_program(self, program):
        return self.programs.get(program)


    def input_exists(self, input):
        return self.inputs.exists(input)

    def add_input(self, input):
        return self.inputs.add(input)
    
    def get_input(self, input):
        return self.inputs.get(input)

    
    def taint_engine_exists(self, taint_engine):
        return self.taint_engines.exists(taint_engine)

    def add_taint_engine(self, taint_engine):
        return self.taint_engines.add(taint_engine)
    
    def get_taint_engine(self, taint_engine):
        return self.taint_engines.get(taint_engine)

   
    def taint_analysis_exists(self, taint_analysis):
        return self.taint_analysess.exists(taint_analysis)

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
        tm = self.taint_mapping_exists(taintm):
        # keep track of set of inputs that we've taint analyzed
        self.taint_inputs.add(tm.inp_uuid)
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
