
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
 


class KnowledgeStorePickle(KnowledgeStore):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.config = ksc
        self.programs = ProgramPickle()
        self.inputs = InputPickle()
        self.taint_engines = TaintEnginePickle()
        self.taint_analyses = TaintAnalyisPickle()


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




    def __fuzzable_byte_set_check(self, fuzzbs):
        assert hasattr(fuzzbs, "label")

    def __fuzzable_byte_set_find(self, fuzzbs):
        labelset = tuple(fuzzbs.label)
        fuzzbs_uuid = md5.new(str(labelset))
        if fuzzbs_uuid in self.fbs:
            return (self.fbs[fuzzbs_uuid], fuzzbs_uuid)
        return (None, fuzzbs_uuid)

    def add_fuzzable_byte_set(self, fuzzbs):
        self.__fuzzable_byte_set_check(fuzzbs)
        (fbs, fuzzbs_uuid) = self.__fuzzable_byte_set_find(fuzzbs)
        if (fbs is None):
            fuzzbs.uuid = fuzzbs_uuid
            self.fbs[fuzzbs_uuid] = fuzzbs
    
    def get_fuzzable_byte_set(self, fuzzbs):
        self.__fuzzable_byte_set_check(fuzzbs)
        (fbs, fuzzbs_uuid) = self.__fuzzable_byte_set_find(fuzzbs)
        if (fbs is None):
            raise FbsNotFound
        return fbs

    
    def __tainted_instruction_check(self, tinstr):
        assert hasattr(tinstr, "pc")
        assert hasattr(tinstr, "module")
        assert hasattr(tinstr, "type")
        assert hasattr(tinstr, "instr_bytes")

    def __tainted_instruction_find(self, tinstr): 
        tinstr_uuid = md5.new(str(tinstr.pc) + tinstr.module + str(tinstr.type) + tinstr.instr_bytes)
        if tinstr_uuid in self.tainted_instructions:
            return (self.tainted_instructions[tinstr_uuid], tinstr_uuid)
        return (None, tinstr_uuid)

    def add_tainted_instruction(self, tinstr):
        self.__tainted_instruction_check(tinstr)
        (ti, tinstr_uuid) = self.__tainted_instruction_find(tinstr)
        if (ti is None):
            tinstr.uuid = tinstr_uuid
            self.tainted_instructions[tinstr_uuid] = tinstr

    def get_tainted_instruction(self, tinstr):
        self.__tainted_instruction_check(tinstr)
        (ti, tinstr_uuid) = self.__tainted_instruction_find(tinstr)
        if (ti is None):
            raise TiNotFound
        return ti


    def __taint_mapping_check(self, taintm):
        assert hasattr(taintm, "inp_uuid")
        assert hasattr(taintm, "fbs_uuid")
        assert hasattr(taintm, "ti_uuid")
        assert hasattr(taintm, "value")
        assert hasattr(taintm, "value_length")
        assert hasattr(taintm, "trace_point")
        assert hasattr(taintm, "min_compute_distance")
        assert hasattr(taintm, "max_compute_distance")


    def __taint_mapping_find(self, taintm):
        taintm_uuid = md5.new(str(taintm.inp_uuid) + str(taintm.fbs_uuid) \
                              + str(taintm.ti_uuid) + str(taintm.value) \
                              + str(taintm.value_length) + str(taintm.trace_point) \
                              + str(taintm.min_compute_distance) \
                              + str(taintm.max_compute_distance)) 
        if taintm_uuid in self.taint_mappings:
            return (self.taint_mappings[taintm_uuid], taintm_uuid)
        return (None, taintm_uuid)

    def add_taint_mapping(self, taintm):
        self.__taint_mapping_check(taintm)
        (tm, taintm_uuid) = self.__taint_mapping_find(taintm)
        if (tm is None):
            taintm.uuid = taintm_uuid
            self.taint_mappings[taintm_uuid] = taintm
    
    def get_taint_mapping(self, taintm):
        self.__taint_mapping_check(taintm)
        (tm, taintm_uuid) = self.__taint_mapping_find(taintm)
        if (tm is None):
            raise TmNotFound
        return tm


    def get_tainted_instructions(self):
        for instr in self.tainted_instructions:
            yield instr
        

    def get_taint_inputs(self):
        
            
            
