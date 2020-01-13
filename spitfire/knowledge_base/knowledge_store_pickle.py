
"""
A very simple in-memory and pickle-based knowledge store

>>> import md5
>>> m = md5.new()
>>> m.update("Nobody inspects")
>>> m.update(" the spammish repetition")
>>> m.digest()


"""

import md5


class KnowledgeStorePickle(KnowledgeStore):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.config = ksc
        self.programs = []
        self.inputs = []
        self.taint_engines = []
        self.taint_analyses = []


    def __program_check(self, program):
        assert hasattr(program,"name")
        assert hasattr(program,"filepath")
        assert hasattr(program,"git_hash")
    
    # find this program in the store (ignore uuid field)
    def __program_find(self, program):
        program_uuid = md5.new(program.name + program.filepath + program.git_hash)
        if program_uuid in self.programs:
            return (self.programs[program_uuid], program_uuid)
        return (None, program_uuid)

    # add program to knowledge store if not already there
    def add_program(self, program):
        self.__program_check(program)
        (prg, program_uuid) = self.__program_find(program)
        if prg is None:
            program.uuid = program_uuid
            self.programs[program_uuid] = program
            return program
        return prg
    
    def get_program(self, program):
        self.__program_check(program)
        (prg, program_uuid) = self.__program_find(program)
        if prg is None:            
            raise ProgNotFound
        return prg

    def program_exists(self, program):
        self.__program_check(program)
        p = self.__program_find(program)
        return (not (p is None))


    def __input_check(self, inp):
        assert(hasattr(inp,"filename"))

    def __input_find(self, inp):
        inp_uuid = md5.new(inp.filepath)
        if inp_uuid in self.inputs:
            return (self.inputs[inp_uuid], inp_uuid)
        return (None, inp_uuid)

    def add_program(self, inp):
        self.__input_check(inp)
        (i, i_uuid) = self.__input_find(inp)
        if i is None:
            inp.uuid = i_uuid
            self.inputs[i_uuid] = inp
            return inp
        return i

    def get_program(self, inp):
        self.__input_check(inp)
        (i, i_uuid) = self.__input_find(inp)
        if i is None:
            raise InpNotFound
        return i

    def input_exists(self, inp):
        self.__input_check(inp)
        i = self.__input_find(inp)
        return (not (i is None))


    def get_input(self, inp):
        self.__input_check(inp)        
        inp_bytes = open(inp.filepath).read()
        inp_uuid = md5.new(inp_bytes)
        i = self.__input_find(inp)
        if not (i is None):
            assert i.uuid == inp_uuid
            return i
        i = spitfire_pb2.Input(uuid=inp_uuid, filepath=inp.filepath)
        self.inputs.append(i)
        return i


    # XXX 
    # TO DO 

    def corpus_exists(self, corp):
        raise NotImplemented

    def get_corpus(self, corp):
        raise NotImplemented

    def experiment_exists(self, experiment):
        raise NotImplemented

    def get_experiment(self, experiment):
        raise NotImplemented


    def __taint_engine_check(self, taint_engine):
        assert hasattr(taint_engine,"name")
        assert hasattr(taint_engine,"install_string")
        

    def __taint_engine_find(self, taint_engine):
        for te in self.taint_engines:
            if te.name == taint_engine.name \
               and te.install_string == taint_engine.install_string:
                return te
        return None

    def taint_engine_exists(self, taint_engine):
        self.__taint_engine_check(taint_engine)
        te = self.__taint_engine_find(taint_engine)
        return (not (te is None))

    def get_taint_engine(self, taint_engine):
        self.__taint_engine_check(taint_engine)
        te_uuid = md5.new(taint_engine.name + taint_engine.install_string)
        te = self.__taint_engine_find(taint_engine)
        if not (te is None):
            assert te.uuid == te_uuid
            return te
        te = spitfire_pb2.TaintEngine(uuid=te_uuid, name=taint_engine.name, \
                                      install_string=taint_engine.install_string)
        self.taint_engines.append(te)
        return te


    def __taint_analysis_check(self, taint_analysis):
        assert hasattr(taint_analysis, "taint_engine")
        assert hasattr(taint_analysis, "program")
        assert hasattr(taint_analysis, "input")


    def __taint_analysis_find(self, taint_analysis):
        for ta in self.taint_analyses:
            if ta.taint_engine == taint_analysis.taint_engine \
               and ta.program == taint_analysis.program \
               and ta.input == taint_analysis.input:
                return ta
            return None

    def taint_analysis_exists(self, taint_analysis):
        self.__taint_analysis_check(taint_analysis)
        ta = self.__taint_analysis_find(taint_analysis)
        return (not (ta is None))

    def get_taint_analysis(self, taint_analysis):
        self.__taint_analysis_check(taint_analysis)
        ta_uuid = md5.new(taint_analysis.taint_engine + \
                          taint_analysis.program + \
                          taint_analysis.input)
        ta = self.__taint_analysis_find(taint_analysis)
        if not (ta is None):
            assert ta.uuid == ta_uuid
            return ta
        ta = spitfire_pb2.TaintAnalysis(uuid=ta_uuid, \
                                        taint_engine=taint_analysis.engine, \
                                        program=taint_analysis.program \
                                        input=taint_analysis.input)
        self.taint_analyses.append(ta)
        self.taint_inputs.append(ta.input)
        return ta



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
        
            
            
