#!/usr/bin/python3

"""

Create recording.  Run replay with taint analysis.  Ingest results to knowledge base

Note: knowledge base server must be up and running and initialized.  

Usage:

panda_taint.py fuzz_config input_filename


"""

import sys
import docker
import logging
import os

this_dir = os.path.dirname(a_module.__file__)

sys.path.append("

>>> os.path.abspath(os.path.join(p, ".."))                                                                                                                    


import spitfire.knowledge_base as knowledge_base
from google.protobuf import text_format

log = logging.getLogger(__name__)


fuzzing_config_dir = sys.argv[1]
input_filepath = sys.argv[2]



@hydra.main(config_path=fuzzing_config_dir)
def main(cfg):

    # channel to talk to kb server
    kbc = grpc.insecure_channel("%s:%s" % (cfg.knowledge_base.host, cfg.knowledge_base.port))
    kbs = spitfire_pb2_grpc.KnowledgeBaseStub(kbc)

    # get canonical representations for all of these things
    program = kbs.GetProgram(cfg.program)
    te_msg = spitfire_pb2.TaintEngine(name="panda", clone_string=cfg.taint.panda.clone_string)
    taint_engine = kbs.GetTaintEngine(te_msg)
    inp_msg = spitfire_pb2.Input(filepath=input_filepath)
    taint_input = kbs.GetInput(inp_msg)

    # if we have already performed this taint analysis, bail
    ta_msg = spitfire_pb2.TaintAnalysis(taint_engine=taint_engine.uuid, \
                                        program=program.uuid, \
                                        input=taint_input.uuid)
    if (kbs.TaintAnalysisExists(ta_msg)):
        log.info("Taint analysis already performed for taint_engine=[%s] program=[%s] input=[%s]" \
                 % (text_format.MessageToString(taint_engine), \
                    text_format.MessageToString(program), \
                    text_format.MessageToString(taint_input)))                    
        return 
    
    # canonical representation of this taint analysis
    taint_analysis = kbs.GetTaintAnalysis(ta_msg)

    log.info("Taint analysis proceeding for taint_engine=[%s] program=[%s] input=[%s]" \
             % (text_format.MessageToString(taint_engine), \
                text_format.MessageToString(program), \
                text_format.MessageToString(taint_input)))
    
    client = docker.from_env()

    # create recording
    (prog_dir, progname) = os.path.split(program.filepath)
    (input_dir, dc) = os.path.split(taint_input.filepath)
    transfer_dir = cfg.taint.panda.transfer_dir
    volume_dict = {}
    volume_dict[prog_dir] = {'bind': prog_dir, 'mode': 'rw'}
    volume_dict[input_dir] = {'bind': input_dir, 'mode': 'rw'}
    volume_dict[transfer_dir] = {'bind': transfer_dir, 'mode': 'rw'}
    cmd = "panda/panda/scripts/run_debian.py --replaybase=" + progname + " " + program.filepath + " " + taint_input + filepath
    client.containers.run(cfg.taint.panda.container_name, cmd, volumes=volume_dict)

    # move the recording
    pshort = program.shortname
    # path to replay we just created
    this_replay_pfx = os.path.join("replays", os.path.join(pshort, pshort))
    # and this is where we will save it for later
    spitfire_replays_dir = os.path.join(fcp.fs.replays_dir, pshort)
    cmd = "mv %s* %s" % (replay_pfx, spitfire_replays_dir)
    # pfx of saved replay
    replay_pfx = os.path.join(spitfire_replays_dir, pshort)

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

        kb_stub = spitfire_pb2_gprc.SpitfireStub(kb_channel)

        # get msg for taint engine
        te = spitfire_pb2.TaintEngine(install_string = panda_install_string)



    # input should be a filename
    # let's get its uuid in canonical spitfire way (md5sum of contents)
    input_uuid = spitfire.get_input_uuid(input_filename)

        # get canonical input msg from kb
        im = spitfire_pb2.Input(uuid = input_uuid)
        input_msg = kb_stub.Getaint_input(im)




    # japan 
"""
