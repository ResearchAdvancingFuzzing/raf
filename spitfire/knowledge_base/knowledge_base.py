#!/usr/bin/python3.6

import os
import sys
import logging
import grpc
import hydra

from concurrent import futures


# walk up the path to find 'spitfire' and add that to python path 
# at most 10 levels up?  
                                                                                                                                                                                                                                                                                          
p = os.path.abspath(__file__)
for i in range(10):
    (hd, tl) = os.path.split(p)
    if tl == "spitfire":
        print("adding path " + p)
        print("adding path " + hd)
        sys.path.append(p)
        sys.path.append(hd)
        sys.path.append(p + "/protos")
        break
    p = hd


import knowledge_store_pickle as ks

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

fuzzing_config_dir = "/home/tleek/git/raf/spitfire/config/expt1"

class KnowledgeBase(kbpg.KnowledgeBaseServicer):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.ks = ks.KnowledgeStorePickle(ksc.knowledge_store)

    # Determines if item is already in the knowledge store
    # All of these return KnowledgeBaseResult with success=True to indicate 
    # that the item exists.  success=False otherwise
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


    # Add item to the ks (or not if already there)
    # Return canonical message for each of these, with
    # uuid filled in.
    def AddProgram(self, program):        
        return ks.add_program(program)

    def AddInput(self, input):        
        return ks.add_input(input)

    def AddCorpus(self, corpus):        
        return ks.add_corpus(corpus)

    def AddExperiment(self, experiment):        
        return ks.add_experiment(experiment)

    def AddTaintEngine(self, taint_engine):        
        return ks.add_taint_engine(taint_engine)

    def AddTaintAnalysis(self, taint_analysis):        
        return ks.add_tain_tanalysis(taint_analysis)


    # obtains canonical protobuf repr for each if its in the kb
    # exception if its not there
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
        return ks.get_taint_analysis(taint_engine, program, inp)


    # Returns KnowledgeBaseResult
    # note, these fbs should be unique (no dups) but shouldt have uuids
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
            return(KnowledgeBaseResult(success=True, message="All taint mappings added"))
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


@hydra.main(config_path=fuzzing_config_dir)
def serve(cfg):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    kbpg.add_KnowledgeBaseServicer_to_server(KnowledgeBase(cfg), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()


