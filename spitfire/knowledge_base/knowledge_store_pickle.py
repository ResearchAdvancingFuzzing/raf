
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
        for p in self.programs:
            if p.name == program.name \
               and p.filepath == program.filepath \
               and p.git_hash == program.git_hash:
                return p
        return None


    def program_exists(self, program):
        self.__program_check(program)
        p = self.__program_find(program)
        return (not (p is None))

     
    def get_program(self, program):
        self.__program_check(program)
        program_bytes = open(program.filepath).read()
        program_uuid = md5.new(program_bytes)
        # if this program is already in the knowledge store, return it
        # in its canonical representation
        p = self.__program_find(program)
        if not (p is None):
            assert p.uuid == program_uuid
            return p
        # its not there -- create, add, and return it
        p = spitfire_pb2.Program(uuid=program_uuid, name=program.name, \
                                 filepath=program.name, git_hash=program.git_hash)
        self.program.append(p)
        return p

    
    def __input_check(self, inp):
        assert(hasattr(inp,"filename"))


    def __input_find(self, inp):
        for i in self.inputs:
            if i.filename == inp.filename:
                return i
        return None


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
        return ta


