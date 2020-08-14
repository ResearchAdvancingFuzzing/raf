#!/usr/bin/python3.6

import os
import sys
import logging
import grpc
import hydra

from concurrent import futures

# walk up the path to find 'spitfire' and add that to python path 
# at most 10 levels up?  

import knowledge_store_pickle as ks
#import protos.knowledge_base_pb2 as kbp
#import protos.knowledge_base_pb2_grpc as kbpg

namespace = os.environ.get("NAMESPACE")
print(namespace)
spitfire_subdir = os.environ.get("SPITFIRE_DIR")
print(spitfire_subdir)
#sys.path.append("/")
spitfire_dir = "/%s%s" % (namespace, spitfire_subdir)
#spitfire_dir = "/home/hpreslier/raf/spitfire"
#print(spitfire_dir)
sys.path.append(spitfire_dir)
sys.path.append(spitfire_dir + "/protos") 
#assert (not (spitfire_dir is None))
import knowledge_base_pb2 as kbp
import knowledge_base_pb2_grpc as kbpg
#import spitfire.protos.knowledge_base_pb2 as kbp
#import spitfire.protos.knowledge_base_pb2_grpc as kbpg

fuzzing_config_dir = f"{spitfire_dir}/config"

class KnowledgeBase(kbpg.KnowledgeBaseServicer):
    
    # ksc is knowledge_store config
    def __init__(self, ksc):
        self.ks = ks.KnowledgeStorePickle(ksc)


    def Pause(self, empty, context):
        return kbp.KnowledgeBaseResult(success=self.ks.pause(), \
                                       message="None")

    def Run(self, empty, context):
        return kbp.KnowledgeBaseResult(success=self.ks.run(), \
                                       message="None")
    
    def GetMode(self, empty, context):
        return kbp.FuzzingManagerMode(type=self.ks.get_fm_mode())
    
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

    def ExecutionExists(self, execution, context):
        return kbp.KnowledgeBaseResult(success=self.ks.execution_exists(execution), \
                                       message="None")




    # Add item to the ks (or not if already there)
    # Return canonical message for each of these, with
    # uuid filled in.
    def AddTarget(self, program, context):      
        (was_new, p) = self.ks.add_target(program)
        if was_new: 
            print("Target added: %s" % str(p.uuid), flush=True) 
            print(p) 
        return p

    def AddInput(self, inp, context):        
        (was_new, i) = self.ks.add_input(inp)
        if was_new:
            print("Input added: %s" % str(i.uuid), flush=True)
            print(i, flush=True)
        return i

    def AddCorpus(self, corpus, context):        
        (was_new, c) = self.ks.add_corpus(corpus)
        if was_new:
            print("Corpus added: %s" % str(c.uuid), flush=True)
            print(c)
        return c

    def AddExperiment(self, experiment, context):        
        (was_new, e) = self.ks.add_experiment(experiment)
        if was_new:
            print("Experiment added: %s" % str(e.uuid), flush=True)
        return e

    def AddAnalysisTool(self, tool, context):        
        (was_new, te) = self.ks.add_analysis_tool(tool)
        if was_new:
            print("Analysis Tool added: %s", te.uuid, flush=True)
        return te

    def AddAnalysis(self, analysis, context):        
        (was_new, ta) = self.ks.add_analysis(analysis)
        if was_new:
            print("Analysis added: %s" % ta.uuid, flush=True)
        return ta

    def AddModules(self, module_itr, context):
        for mod in module_itr:
            (was_new, m) = self.ks.add_module(mod)
            if was_new:
                print("Module added: %s" % m.uuid, flush=True)
            yield m

    def AddAddresses(self, address_itr, context):
        for addr in address_itr:
            (was_new, a) = self.ks.add_address(addr)
            if was_new:
                print("Address added: %s" % a.uuid, flush=True)
            yield a

    def AddEdgeCoverage(self, coverage_itr, context):
        for edge in coverage_itr:
            (was_new, e) = self.ks.add_edge_coverage(edge)
            if was_new:
                print("Edge added: " + str(e.uuid), flush=True)
                #print(e, flush=True)
            yield e

    def AddEdge(self, edge, context):
        (was_new, e) = self.ks.add_edge(edge)
        return e            
    
    def EdgeExists(self, edge, context): 
        return kbp.KnowledgeBaseResult(success=self.ks.edge_exists(edge), \
                                       message="None")

    def AddExecution(self, execution, context): 
        (was_new, te) = self.ks.add_execution(execution) 
        if was_new: 
            print("Execution added: %s" % te.uuid, flush=True)
        return te 

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

    def GetExecution(self, execution, context):
        return self.ks.get_execution(execution) 

    # Returns KnowledgeBaseResult
    # note, these fbs should be unique (no dups) but shouldt have uuids
    def AddFuzzableByteSets(self, fbs_iterator, context):
        for f in fbs_iterator:
            (was_new, fbs) = self.ks.add_fuzzable_byte_set(f)
            if was_new:
                print("Fbs added: " + str(fbs.uuid), flush=True)
            yield fbs
    
    def AddTaintedInstructions(self, ti_iterator, context): 
        for t in ti_iterator: 
            (was_new, ti) = self.ks.add_tainted_instruction(t) 
            if was_new:
                print("Ti added: " + str(ti.uuid), flush=True)
            yield ti
    
    def TaintedInstructionExists(self, ti, context): 
        return kbp.KnowledgeBaseResult(
                success=self.ks.tainted_instruction_exists(ti), message="None")
    # Returns KnowledgeBaseResult
    def AddTaintMappings(self, tm_iterator, context):
        for t in tm_iterator:
            (was_new, tm) = self.ks.add_taint_mapping(t)
            if was_new:
                print("Tm added: " + str(tm.uuid), flush=True)
            yield tm

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

    def GetTaintMappingsForFuzzableByteSet(self, fbs, context):
        for tm in self.ks.get_taint_mappings_for_fuzzable_byte_set(fbs): 
            yield tm

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
    
    def GetEdgeCoverageForInput(self, inp, context): 
        for ec in self.ks.get_edge_coverage_for_input(inp):
            yield ec

    def GetEdgeCoverage(self, emp, context):
        for ec in self.ks.get_edge_coverage():
            yield ec

    def GetEdges(self, emp, context):
        for edge in self.ks.get_edges():
            yield edge

    def GetEdgesForInput(self, inp, context):
        for edge in self.ks.get_edges_for_input(inp):
            yield edge

    def GetNumInputsForEdge(self, edge, context):
        return kbp.IntMessage(val=self.ks.get_num_inputs_for_edge(edge))
            
    def GetInputsForEdge(self, edge, context):
        for inp in self.ks.get_inputs_for_edge(edge):
            yield inp            
           
    def GetPendingInputs(self, emp, context): 
        for inp in self.ks.get_pending_inputs(): 
            yield inp

    def MarkInputAsPending(self, inp, context): 
        print("Marking input as pending", flush=True)
        new_inp = self.ks.mark_input_as_pending(inp)
        print(new_inp, flush=True) 
        return new_inp
        #return self.ks.mark_input_as_pending(inp) 

    def GetExecutionInputs(self, emp, context):
        for inp in self.ks.get_execution_inputs():
            yield inp

    def GetInputsWithCoverage(self, emp, context):
        for inp in self.ks.get_inputs_with_coverage():
            yield inp

    def GetInputsWithoutCoverage(self, emp, context):
        for inp in self.ks.get_inputs_without_coverage():
            yield inp

    def GetSeedInputs(self, emp, context):
        for inp in self.ks.get_seed_inputs():
            yield inp

    def GetInputById(self, uuid, context):
        return self.ks.get_input_by_id(uuid) 

    def GetEdgeById(self, uuid, context):
        return self.ks.get_edge_by_id(uuid)

    def AddFuzzingEvent(self, event, context):
        self.ks.add_fuzzing_event(event)
        return kbp.Empty()
        
#    def AddFuzzingEvents(self, fuzzing_events_iterator, context):
#        for fe in fuzzing_events_iterator:
#            self.ks.add_fuzzing_event(fe)
#        return kbp.Empty()

    def GetFuzzingEvents(self, fuzzing_event_filter, context):
        start_time = None
        end_time = None
        if fuzzing_event_filter.HasField("begin"):
            start_time = fuzzing_event_filter.start.ToDatetime()
        if fuzzing_event_filter.HasField("end"):
            end_time = fuzzing_event_filter.end.ToDatetime()
        for fe in self.ks.get_all_fuzzing_events():
            filtered = False
            t = fe.timestamp.ToDatetime()
            # event is outside time window specified
            if not (start_time is None) and (t < start_time):
                filtered |= True
            if not (end_time is None) and (t > end_time):
                filtered |= True
            # the event type for this fuzzing event
            typ = fe.WhichOneof("event_type")
            assert (not (typ is None))
            # filtering decision exists for this event type 
            # and True means filter it (discard)
#            print ("typ = %s" % typ)
            if hasattr(fuzzing_event_filter,typ) and getattr(fuzzing_event_filter,typ) == False:
                filtered |= True
            if not filtered:
                yield fe
    

    
    
@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def serve(cfg):
    print(cfg.pretty(), flush=True)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1000), maximum_concurrent_rpcs=16)
    kbpg.add_KnowledgeBaseServicer_to_server(KnowledgeBase(cfg), server)
    server.add_insecure_port("[::]:%d" % cfg.knowledge_base.port)
    print(cfg.knowledge_base.port)
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()


