#!/usr/bin/python3.6

import logging
import grpc
import hydra

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

import knowledge_base_pb2
import knowledge_base_pb2_grpc
import knowledge_store as ks


class KnowledgeBase(spitfire_pb2_grpc.KnowledgeBaseServicer):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.ks = ks.KnowledgeStore(kcs.knowledge_store)

    # determines if any of these are already in the kb
    # All of these return KnowledgeBaseResult
    def ProgramExists(self, program):
        return ks.program_exists(program)

    def InputExists(self, inp):
        return ks.input_exists(inp)

    def CorpusExists(self, corpus):
        return ks.corpus_exists(corpus)

    def ExperimentExists(self, experiment):
        return ks.experiment_exists(experiment)

    def TaintEngineExists(self, taint_engine):
        return ks.taint_engine_exists(taint_engine)

    def TaintAnlysisExists(self, taint_analysis):
        return ks.taint_analysis_exists(taint_analysis)
    
    # obtains canonical representation for each in the kb
    # note: adds if not present
    # Returns: Program
    def GetProgram(self, program):        
        return ks.get_program(program)
        
    # Returns Input
    def GetInput(self, inp):
        return ks.get_input(inp)

    # Returns Corpus
    def GetCorpus(self, corp):
        return ks.get_corpus(corp)

    # Returns Experiment
    def GetExperiment(self, experiment):
        return ks.get_experiment(experiment)

    # Returns TaintEngine
    def GetTaintEngine(self, taint_engine):
        return ks.get_taint_engine(taint_engine)

    # Returns TaintAnalysis
    def GetTaintAnalysis(self, taint_engine, program, inp):
        return ks.get_taint_analysis(taint_engine, program, inp):


    # Returns KnowledgeBaseResult
    def AddFuzzableByteSets(self, fbs_iterator):
        try:
            for fbs in fbs_iterator:
                ks.add_fuzzable_byte_set(fbs)
            return(KnowledgeBaseResult(success=True, message="All fbs added"))
        except Exception as e:
            return(KnowledgeBaseResult(success=False, message=str(e)))

    # Returns KnowledgeBaseResult
    def AddTaintedInstructions(self, ti_iterator):
        try:
            for ti in ti_iterator:
                ks.add_tainted_instruction(ti)
            return(KnowledgeBaseResult(success=True, message="All tainted instructions added"))
        except Exception as e:
            return(KnowledgeBaseResult(success=False, message=str(e)))        

    # Returns KnowledgeBaseResult
    def AddTaintMappings(self, tm_iterator):
        try:
            for tm in tm_iterator:
                ks.add_taint_mapping(tm)
            return(KnowledgeBaseResult(success=True, message="All tainted mappings added"))
        except Exception as e:
            return(KnowledgeBaseResult(success=False, message=str(e)))        

    # iterator over tainted instructions in the knowledge base
    def GetTaintedInstructions(self, emp):
        for instr in ks.get_tainted_instructions():
            yield instr

    # iterator over inputs that have been taint analyzed
    def GetTaintInputs(self, emp):
        for inp in ks.get_taint_inputs():
            yield inp

    # iterator over inputs that taint this instruction
    def GetTaintInputsForTaintedInstruction(self, instr):
        for inp in ks.get_taint_inputs_for_tainted_instruction(instr):
            yield inp

    # iterator over fbs for this input
    def GetFuzzableByteSetsForTaintInput(self, inp):
        for fbs in ks.get_fuzzable_byte_sets_for_taint_input(inp):
            yield fbs

    # iterator over instructions that are tainted for this input
    def GetTaintedInstructionsForTaintInput(self, inp):
        for instr in ks.get_tainted_instructions_for_taint_input(inp):
            yield instr

    # interator over taint mappings for this inp-fbs/instr key
    def GetTaintMappings(self, tmk):
        for tm in ks.get_taint_mappings(tmk):
            yield tm


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    knowledge_base_pb2_grpc.add_KnowledgeBaseServicer_to_server(KnowledgeBase(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()


