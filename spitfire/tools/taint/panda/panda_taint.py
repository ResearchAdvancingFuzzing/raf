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

from os.path import join,basename

import grpc
import hydra
import subprocess as sp

# walk up the path to find 'spitfire' and add that to python path
# at most 10 levels up?
p = os.path.abspath(__file__)
spitfire_dir = None
for i in range(10):
    (hd, tl) = os.path.split(p)
    if tl == "spitfire":
        print ("p = %s" % p)
        sys.path.append(p)
        spitfire_dir = p
        sys.path.append(hd)
        sys.path.append(p + "/protos")
        break
    p = hd

assert (not (spitfire_dir is None))

import spitfire.protos.knowledge_base_pb2 as kbp
import spitfire.protos.knowledge_base_pb2_grpc as kbpg

import knowledge_base 
from google.protobuf import text_format

log = logging.getLogger(__name__)


# this should really be argv[1]
fuzzing_config_dir = "%s/config/expt1" % spitfire_dir

# and this should be argv[2]





@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def run(cfg):
#    print(cfg.pretty())

    # channel to talk to kb server
    with grpc.insecure_channel("%s:%s" % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
        kbs = kbpg.KnowledgeBaseStub(channel)

        # get canonical representations for all of these things
        target_msg = kbp.Target(name=cfg.target.name, \
                                source_hash=cfg.target.source_hash)
        target = kbs.AddTarget(target_msg)
        
        panda_msg = kbp.AnalysisTool(name="panda", \
                                   source_string=cfg.taint.source_string,
                                   type=kbp.AnalysisTool.AnalysisType.TAINT)
        panda = kbs.AddAnalysisTool(panda_msg)

        print("input file is [%s]" % cfg.taint.input_file)
        input_msg = kbp.Input(filepath=cfg.taint.input_file)
        taint_input = kbs.AddInput(input_msg)

        # if we have already performed this taint analysis, bail
        taint_analysis_msg = kbp.Analysis(tool=panda.uuid, \
                                          target=target.uuid, \
                                          input=taint_input.uuid)
        taint_analysis = kbs.AddAnalysis(taint_analysis_msg)

        msg_end = "\ntool:\n%s\ntarget:\n%s\ninput:\n%s\n" \
                  % (text_format.MessageToString(panda), \
                     text_format.MessageToString(target), \
                     text_format.MessageToString(taint_input))

        if taint_analysis.complete:
            log.info("Taint analysis already performed for %s" % msg_end)
            return
        
        log.info("Taint analysis proceeding for %s" % msg_end)
        
        log.info("Creating recording")
        
        run_sh = join(join(join(cfg.taint.harness_dir, "targets"), \
                           "%s-%s-64bit" % (cfg.target.name, \
                                            cfg.target.source_hash)), "run.sh")
        retv = sp.check_call([run_sh, taint_input.filepath])
        replay_dir = os.getcwd()
        replay_pfx = join(os.getcwd(), basename(taint_input.filepath))

        if retv == 0:
            log.info("Recording created: pfx=%s" % replay_pfx)
        else:
            raise PandaTaintFailed("Couldn't create recording")

        
        client = docker.from_env()
        
        transfer_dir = os.getcwd()
        volume_dict[transfer_dir] = {'bind': "/transfer"}
        cmd = "panda/build/x
        client.containsers.run(cfg.taint.panda_container,  
        
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
