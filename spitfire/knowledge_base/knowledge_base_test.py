

"""The Python implementation of the GRPC helloworld.Greeter client."""

import os
import sys

import logging

import grpc

                                                                                                                             
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



import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg


log = logging.getLogger(__name__)


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = kbpg.KnowledgeBaseStub(channel)
        prog1_msg = kbp.Program(name="gzip", filepath="/usr/bin/gzip", \
                                git_hash="ksjdfhsdjkfhds")

        prog2_msg = kbp.Program(name="cat", filepath="/usr/bin/cat", \
                                git_hash="kaj;sdfhak;jsdfh")

        def add_program(pm):
            print("Adding program [%s]" % pm.name)
            return stub.AddProgram(pm)
            
        def check_program(pm):
            print("Checking on program [%s] " % pm.name, end="")
            response = stub.ProgramExists(pm)
            if response.success:
                print(" -- Exists")
            else:
                print(" -- NotThere")

        check_program(prog1_msg)
        prog1 = add_program(prog1_msg)
        check_program(prog1_msg)

        check_program(prog2_msg)
        prog2 = add_program(prog2_msg)
        check_program(prog2_msg)

        # make sure we can check twice
        check_program(prog1_msg)
        check_program(prog2_msg)

        # if we get those programs (msg with uuid not filled in)
        # we should get same uuid
        prog1_1 = stub.GetProgram(prog1_msg)
        assert (prog1_1.uuid == prog1.uuid)
        prog2_1 = stub.GetProgram(prog2_msg)
        assert (prog2_1.uuid == prog2.uuid)


        inp1_msg = kbp.Input(filepath="/etc//paswd")
        inp2_msg = kbp.Input(filepath="/var/stuff.txt")

        def add_input(im):
            print("Adding input [%s]" % im.filepath)
            return stub.AddInput(im)

        def check_input(im):
            print("Checking on input [%s] " % im.filepath, end="")
            response = stub.InputExists(im)
            if response.success:
                print(" -- Exists")
            else:
                print(" -- NotThere")

        check_input(inp1_msg)
        inp1 = add_input(inp1_msg)
        check_input(inp1_msg)

        check_input(inp2_msg)
        inp2 = add_input(inp2_msg)
        check_input(inp2_msg)

        check_input(inp1_msg)
        check_input(inp2_msg)

        inp1_1 = stub.GetInput(inp1_msg)
        assert (inp1_1.uuid == inp1.uuid)
        inp2_1 = stub.GetInput(inp2_msg)
        assert (inp2_1.uuid == inp2.uuid)

        
        te1_msg = kbp.TaintEngine(name="pandataint0", clone_string="git clone -b spitfire_0 https://github.com/panda-re/panda.git")
        te2_msg = kbp.TaintEngine(name="pandataint2", clone_string="git clone -b spitfire_2 https://github.com/panda-re/panda.git")

        def add_taint_engine(te):
            print("Adding taint_engine [%s]" % te.name)
            return stub.AddTaintEngine(te)

        def check_taint_engine(te):
            print("Checking on taint_engine [%s] " % te.name, end="")
            response = stub.TaintEngineExists(te)
            if response.success:
                print(" -- Exists")
            else:
                print(" -- NotThere")            

        check_taint_engine(te1_msg)
        te1 = add_taint_engine(te1_msg)
        check_taint_engine(te1_msg)

        check_taint_engine(te2_msg)
        te2 = add_taint_engine(te2_msg)
        check_taint_engine(te2_msg)

        check_taint_engine(te1_msg)
        check_taint_engine(te2_msg)

        te1_1 = stub.GetTaintEngine(te1_msg)
        assert (te1_1.uuid == te1.uuid)
        te2_1 = stub.GetTaintEngine(te2_msg)
        assert (te2_1.uuid == te2.uuid)


        def add_taint_analysis(ta):
            print("Adding taint_analysis [%s]" % (str(ta)))
            return stub.AddTaintAnalysis(ta)
            

        def check_taint_analysis(ta):
            print("Checking on taint_analysis [%s] " % (str(ta)), end="")
            response = stub.TaintAnalysisExists(ta)
            if response.success:
                print(" -- Exists")
            else:
                print(" -- NotThere")            

        ta1_msg = kbp.TaintAnalysis(taint_engine=te1.uuid, program=prog1.uuid, input=inp1.uuid)
        ta2_msg = kbp.TaintAnalysis(taint_engine=te1.uuid, program=prog2.uuid, input=inp1.uuid)
        
        check_taint_analysis(ta1_msg)
        ta1 = add_taint_analysis(ta1_msg)
        check_taint_analysis(ta1_msg)

        check_taint_analysis(ta2_msg)
        ta2 = add_taint_analysis(ta2_msg)
        check_taint_analysis(ta2_msg)

        check_taint_analysis(ta1_msg)
        check_taint_analysis(ta2_msg)

        ta1_1 = stub.GetTaintAnalysis(ta1_msg)
        assert(ta1_1.uuid == ta1.uuid)
        ta2_1 = stub.GetTaintAnalysis(ta2_msg)
        assert(ta2_1.uuid == ta2.uuid)


        fbs1 = kbp.FuzzableByteSet(label=list(set([1,2,3])))
        fbs2 = kbp.FuzzableByteSet(label=list(set([2,3,4,5,6])))
        fbs3 = kbp.FuzzableByteSet(label=list(set([22,23,34,35])))
    
        fbss = [fbs1, fbs2, fbs3]
        
        def fbs_iterator(x):
            for fbs in x:
                yield fbs
        
        resp = stub.AddFuzzableByteSets(fbs_iterator(fbs_iterator(fbss)))
        # this should say 3 were added
        print(resp.message)

        resp = stub.AddFuzzableByteSets(fbs_iterator(fbs_iterator(fbss)))
        # this should say 0 were added
        print(resp.message)

        ti1 = kbp.TaintedInstruction(pc=0xdeadbeef, module="/some/module/thing.so", type="jmp", instr_bytes=bytes("abcd", "utf-8"))
        ti2 = kbp.TaintedInstruction(pc=0xfeedbeef, module="/usr/bin//thang", type="branch", instr_bytes=bytes("98724", "utf-8"))

        tis = [ti1, ti2]

        def ti_iterator(x):
            for ti in x:
                yield ti

        resp = stub.AddTaintedInstructions(ti_iterator(tis))
        # this should say 2 added
        print(resp.message)

        resp = stub.AddTaintedInstructions(ti_iterator(tis))
        # and this should say 0 added
        print(resp.message)






if __name__ == '__main__':
    logging.basicConfig()
    run()
