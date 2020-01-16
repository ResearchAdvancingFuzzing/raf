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
import protos.knowledge_base_pb2 as kbp
import protos.knowledge_base_pb2_grpc as kbpg

fuzzing_config_dir = "../config/expt1"

class KnowledgeBase(kbpg.KnowledgeBaseServicer):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.ks = ks.KnowledgeStorePickle(ksc)

    # Determines if item is already in the knowledge store
    # All of these return KnowledgeBaseResult with success=True to indicate 
    # that the item exists.  success=False otherwise
    def ProgramExists(self, program, context):
        return kbp.KnowledgeBaseResult(success=self.ks.program_exists(program), \
                                       message="None")

    def InputExists(self, inp, context):
        return kbp.KnowledgeBaseResult(success=self.ks.input_exists(inp), \
                                       message="None")                                       

    def CorpusExists(self, corpus, context):
        return kbp.KnowledgeBaseResult(success=self.ks.corpus_exists(corpus), \
                                       message="None")

    def ExperimentExists(self, experiment, context):
        return kbp.KnowledgeBaseResult(success=self.ks.experiment_exists(experiment), \
                                       message="None")

    def TaintEngineExists(self, taint_engine, context):
        return kbp.KnowledgeBaseResult(success=self.ks.taint_engine_exists(taint_engine), \
                                       message="None")

    def TaintAnalysisExists(self, taint_analysis, context):
        return kbp.KnowledgeBaseResult(success=self.ks.taint_analysis_exists(taint_analysis), \
                                       message="None")


    # Add item to the ks (or not if already there)
    # Return canonical message for each of these, with
    # uuid filled in.
    def AddProgram(self, program, context):        
        (was_new, p) = self.ks.add_program(program)
        return p

    def AddInput(self, inp, context):        
        (was_new, i) = self.ks.add_input(inp)
        return i

    def AddCorpus(self, corpus, context):        
        (was_new, c) = self.ks.add_corpus(corpus)
        return c

    def AddExperiment(self, experiment, context):        
        (was_new, e) = self.ks.add_experiment(experiment)
        return e

    def AddTaintEngine(self, taint_engine, context):        
        (was_new, te) = self.ks.add_taint_engine(taint_engine)
        return te

    def AddTaintAnalysis(self, taint_analysis, context):        
        (was_new, ta) = self.ks.add_taint_analysis(taint_analysis)
        return ta


    # obtains canonical protobuf repr for each if its in the kb
    # exception if its not there
    def GetProgram(self, program, context):        
        return self.ks.get_program(program)

    def GetInput(self, inp, context):
        return self.ks.get_input(inp)

    def GetCorpus(self, corp, context):
        return self.ks.get_corpus(corp)

    def GetExperiment(self, experiment, context):
        return self.ks.get_experiment(experiment)

    def GetTaintEngine(self, taint_engine, context):
        return self.ks.get_taint_engine(taint_engine)

    def GetTaintAnalysis(self, taint_analysis, context):
        return self.ks.get_taint_analysis(taint_analysis)


    # Returns KnowledgeBaseResult
    # note, these fbs should be unique (no dups) but shouldt have uuids
    def AddFuzzableByteSets(self, fbs_iterator, context):
        try:
            num_new = 0 
            for fbs in fbs_iterator:
                print ("Adding fbs [%s]" % (str(fbs)))
                (was_new, fbs) = self.ks.add_fuzzable_byte_set(fbs)
                if was_new:
                    num_new += 1
            return(kbp.KnowledgeBaseResult(success=True, message="%d fbs added" % num_new))
        except Exception as e:
            print ("Exception: %s" % str(e))
            return(kbp.KnowledgeBaseResult(success=False, message="AddFuzzableByteSets exception: " + str(e)))

    # Returns KnowledgeBaseResult
    def AddTaintedInstructions(self, ti_iterator, context):
        try:
            num_new = 0
            for ti in ti_iterator:
                print ("Adding ti [%s]" % (str(ti)))
                (was_new, ti) = self.ks.add_tainted_instruction(ti)
                if was_new:
                    num_new += 1
            return(kbp.KnowledgeBaseResult(success=True, message="%d ti added" % num_new))
        except Exception as e:
            print ("Exception: %s" % str(e))
            return(kbp.KnowledgeBaseResult(success=False, message="AddTaintedInstructions exception: " + str(e)))

    # Returns KnowledgeBaseResult
    def AddTaintMappings(self, tm_iterator, context):
        try:
            for tm in tm_iterator:
                self.ks.add_taint_mapping(tm)
            return(KnowledgeBaseResult(success=True, message="All taint mappings added"))
        except Exception as e:
            return(KnowledgeBaseResult(success=False, message=str(e)))        

    # iterator over tainted instructions in the knowledge base
    def GetTaintedInstructions(self, emp, context):
        for instr in self.ks.get_tainted_instructions():
            yield instr

    # iterator over inputs that have been taint analyzed
    def GetTaintInputs(self, emp, context):
        for inp in self.ks.get_taint_inputs():
            yield inp

    # iterator over inputs that taint this instruction
    def GetTaintInputsForTaintedInstruction(self, instr, context):
        for inp in self.ks.get_taint_inputs_for_tainted_instruction(instr):
            yield inp

    # iterator over fbs for this input
    def GetFuzzableByteSetsForTaintInput(self, inp, context):
        for fbs in self.ks.get_fuzzable_byte_sets_for_taint_input(inp):
            yield fbs

    # iterator over instructions that are tainted for this input
    def GetTaintedInstructionsForTaintInput(self, inp, context):
        for instr in self.ks.get_tainted_instructions_for_taint_input(inp):
            yield instr

    # interator over taint mappings for this inp-fbs/instr key
    def GetTaintMappings(self, tmk, context):
        for tm in self.ks.get_taint_mappings(tmk):
            yield tm


@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def serve(cfg):
    print(cfg.pretty())
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    kbpg.add_KnowledgeBaseServicer_to_server(KnowledgeBase(cfg), server)
    server.add_insecure_port("[::]:%d" % cfg.kb_port)
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()


