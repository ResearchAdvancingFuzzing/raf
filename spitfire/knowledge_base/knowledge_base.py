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
    def TargetExists(self, program, context):
        return kbp.KnowledgeBaseResult(success=self.ks.target_exists(program), \
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

    def AnalysisToolExists(self, tool, context):
        return kbp.KnowledgeBaseResult(success=self.ks.analysis_tool_exists(tool), \
                                       message="None")

    def AnalysisExists(self, analysis, context):
        return kbp.KnowledgeBaseResult(success=self.ks.analysis_exists(analysis), \
                                       message="None")


    # Add item to the ks (or not if already there)
    # Return canonical message for each of these, with
    # uuid filled in.
    def AddTarget(self, program, context):        
        (was_new, p) = self.ks.add_target(program)
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

    def AddAnalysisTool(self, tool, context):        
        (was_new, te) = self.ks.add_analysis_tool(tool)
        return te

    def AddAnalysis(self, analysis, context):        
        (was_new, ta) = self.ks.add_analysis(analysis)
        return ta

    def AddModules(self, module_itr, context):
        for mod in module_itr:
            (was_new, m) = self.ks.add_module(mod)
            yield m

    def AddAddresses(self, address_itr, context):
        for addr in address_itr:
            (was_new, a) = self.ks.add_address(addr)
            yield a

    def AddEdgeCoverage(self, coverage_itr, context):
        for edge in coverage_itr:
            (was_new, e) = self.ks.add_edge_coverage(edge)
            print("new edge: " + str(e.uuid))
            yield e
            
    # obtains canonical protobuf repr for each if its in the kb
    # exception if its not there
    def GetTarget(self, program, context):        
        return self.ks.get_target(program)

    def GetInput(self, inp, context):
        return self.ks.get_input(inp)

    def GetCorpus(self, corp, context):
        return self.ks.get_corpus(corp)

    def GetExperiment(self, experiment, context):
        return self.ks.get_experiment(experiment)

    def GetAnalysisTool(self, tool, context):
        return self.ks.get_analysis_tool(tool)

    def GetAnalysis(self, analysis, context):
        return self.ks.get_analysis(taint_analysis)


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
    server.add_insecure_port("[::]:%d" % cfg.knowledge_base.port)
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()


