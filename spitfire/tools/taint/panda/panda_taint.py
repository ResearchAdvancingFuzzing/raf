#!/usr/bin/python3.6

"""

Create recording.  Run replay with taint analysis.  Ingest results to knowledge base

Note: knowledge base server must be up and running and initialized.  

Usage:

panda_taint.py fuzz_config input_filename



panda_taint.py /home/tleek/git/raf/spitfire/config/expt1 /home/tleek/transfer/libxml2/test/slashdot.xml


"""

import sys
import logging
import os

import grpc
import hydra
import docker

# walk up the path to find 'spitfire' and add that to python path
# at most 10 levels up?
p = os.path.abspath(__file__)
for i in range(10):
    (hd, tl) = os.path.split(p)
    if tl == "spitfire":
        sys.path.append(p)
        sys.path.append(hd)
        sys.path.append(p + "/protos")
        break
    p = hd


import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

import knowledge_base 
from google.protobuf import text_format

log = logging.getLogger(__name__)


fuzzing_config_dir = "/home/tleek/git/raf/spitfire/config/expt1"
# sys.argv[1]
input_filepath = "/home/tleek/transfer/libxml2/test/slashdot.xml"
#sys.argv[2]



@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def run(cfg):
    print(cfg.pretty())

    # channel to talk to kb server
    with grpc.insecure_channel("%s:%s" % (cfg.kb_host, cfg.kb_port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        # get canonical representations for all of these things
        prog_msg = kbp.Program(name=cfg.prog_name, \
                               filepath=cfg.prog_filepath, \
                               git_hash=cfg.prog_git_hash)
        program = kbs.AddProgram(prog_msg)
        
        te_msg = kbp.TaintEngine(name="panda", \
                                 clone_string=cfg.panda_clone_string)
        taint_engine = kbs.AddTaintEngine(te_msg)
    
        inp_msg = kbp.Input(filepath=input_filepath)
        taint_input = kbs.AddInput(inp_msg)

        # if we have already performed this taint analysis, bail
        ta_msg = kbp.TaintAnalysis(taint_engine=taint_engine.uuid, \
                                   program=program.uuid, \
                                   input=taint_input.uuid)
        taint_analysis = kbs.AddTaintAnalysis(ta_msg)
        if taint_analysis.complete:
            log.info("Taint analysis already performed for taint_engine=[%s] program=[%s] input=[%s]" \
                     % (text_format.MessageToString(taint_engine), \
                        text_format.MessageToString(program), \
                        text_format.MessageToString(taint_input)))                    
            return 
        
        log.info("Taint analysis proceeding for taint_engine=[%s] program=[%s] input=[%s]" \
                 % (text_format.MessageToString(taint_engine), \
                    text_format.MessageToString(program), \
                    text_format.MessageToString(taint_input)))
        
        client = docker.from_env()
        
        # create recording
        (prog_dir, progname) = os.path.split(program.filepath)
        (input_dir, dc) = os.path.split(taint_input.filepath)
        transfer_dir = cfg.panda_container_transfer_dir
        volume_dict = {}
        volume_dict[prog_dir] = {'bind': prog_dir, 'mode': 'rw'}
        volume_dict[input_dir] = {'bind': input_dir, 'mode': 'rw'}
        volume_dict[transfer_dir] = {'bind': transfer_dir, 'mode': 'rw'}
        
        
        envdict = "\"{'LD_LIBRARY_PATH':'%s/.libs'}\"" % transfer_dir

        cmd = "panda/panda/scripts/run_debian.py -env " + envdict + " --replaybase=" + progname + " " + program.filepath + " " + taint_input.filepath
        client.containers.run(cfg.panda_container_name, cmd, volumes=volume_dict)
        
        # move the recording
        pshort = program.shortname
        # path to replay we just created
        this_replay_pfx = os.path.join("replays", os.path.join(pshort, pshort))
        # and this is where we will save it for later
        knowledge_base_replays_dir = os.path.join(fcp.fs.replays_dir, pshort)
        cmd = "mv %s* %s" % (replay_pfx, knowledge_base_replays_dir)
        # pfx of saved replay
        replay_pfx = os.path.join(knowledge_base_replays_dir, pshort)

"""
    # replay using taint
    pandalog_filename = os.path.join(fcp.fs.pandalogdir, pshort + ".plog")
    cmd = fcp.panda.binary \
          + " -replay " + replay_pfx \
          + " -pandalog " + pandalog_filename \
          + " -os " + fcp.panda.os_string \
          + " -panda file_taint:filename=" + taint_input.name \
          + " -panda asidstory,                                    

    testsmall.bin,pos=1 -panda tainted_branch 

    replays/file-32-1.45/file-32-1.45 " \
          + "-os linux-32-debian:3.2.0-4-686-pae -pandalog " "/fs/prgrams/file/replays/

    "/transfer/toy.plog -panda file_taint:filename=testsmall.bin,pos=1 -panda tainted_branch && panda/panda/scripts/plog_reader.py /transfer/toy.plog > /transfer/toy.plog.txt

    client.containers.run(panda_container_name, "panda/panda/scripts/run_debian.py /transfer/toy /transfer/testsmall.bin && panda/build/i386-softmmu/panda-system-i386 -replay replays/toy/toy -os linux-32-debian:3.2.0-4-686-pae -pandalog /transfer/toy.plog -panda file_taint:filename=testsmall.bin,pos=1 -panda tainted_branch && panda/panda/scripts/plog_reader.py /transfer/toy.plog > /transfer/toy.plog.txt



    # connect to the knowledge base for remainder

    with grpc.insecure_channel('localhost:50059') as kb_channel:

        kb_stub = knowledge_base_pb2_gprc.SpitfireStub(kb_channel)

        # get msg for taint engine
        te = knowledge_base_pb2.TaintEngine(install_string = panda_install_string)



    # input should be a filename
    # let's get its uuid in canonical spitfire way (md5sum of contents)
    input_uuid = spitfire.get_input_uuid(input_filename)

        # get canonical input msg from kb
        im = knowledge_base_pb2.Input(uuid = input_uuid)
        input_msg = kb_stub.Getaint_input(im)




    # japan 
"""



if __name__ == "__main__":
    run()
