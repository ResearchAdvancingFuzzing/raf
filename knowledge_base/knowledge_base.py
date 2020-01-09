
import knowledge_store as ks


class KnowledgeBase(spitfire_pb2_grpc.KnowledgeBaseServicer):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.ks = ks.KnowledgeStore(kcs.knowledge_store)


    # determines if any of these are already in the kb
    # returns true / false
    def ProgramExists(self, program):
        return ks.program_exists(program)

    def InputExists(self, inp):
        return ks.input_exists(inp)

    def CorpusExists(self, corpus):
        return ks.corpus_exists(corpus)

    def ExperimentExists(self, experiment):
        return ks.experiment_exists(experiment)

    def TaintEngineExists(self, tainte_ngine):
        return ks.taint_engine_exists(taint_engine)

    def TaintaAalysisExists(self, taint_analysis):
        return ks.taint_analysis_exists(taint_analysis)

    
    # obtains canonical representation for each in the kb
    # note: adds if not present
    def GetProgram(self, program):        
        return ks.get_program(program)
        
    def GetInput(self, inp):
        return ks.get_input(inp)

    def GetCorpus(self, corp):
        return ks.get_corpus(corp)
    
    def GetExperiment(self, experiment):
        return ks.get_experiment(experiment)

    def GetTaintEngine(self, taint_engine):
        return ks.get_taint_engine(taint_engine)

    def GetTaintAnalysis(self, taint_engine, program, inp):
        return ks.get_taint_analysis(taint_engine, program, inp):


    def AddFuzzableByteSets(fbs_iterator):
        
