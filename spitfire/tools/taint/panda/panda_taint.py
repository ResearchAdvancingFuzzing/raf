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

import subprocess as sp

import grpc
import hydra
import docker

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

        log.info("Connected to knowledge_base")

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

        msg_end = "tool:\n%starget:\n%sinput:\n%s" \
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
        replay_name = basename(taint_input.filepath)
#        replay_pfx = join(os.getcwd(), replay_name)

        if retv == 0:
            log.info("Recording created: %s" % replay_name)
        else:
            raise PandaTaintFailed("Couldn't create recording")

# tleek@ubuntu:~/git/raf/spitfire/tools/taint/panda$ ~/git/panda/build/x86_64-softmmu/panda-system-x86_64 -m 1G -replay ./outputs/2020-02-12/09-21-21/slashdot.xml-panda  -os linux-64-ubuntu:4.15.0-72-generic -panda file_taint:filename=slashdot.xml,pos=1^C

        # now do the taint analysis
        client = docker.from_env()
        
        transfer_dir = os.getcwd()
        volume_dict = {}
        volume_dict[transfer_dir] = {'bind': "/transfer"}

        input_basename = os.path.basename(cfg.taint.input_file)

        pandalog = join("/transfer", "taint.plog")

        cmd = "/panda/build/x86_64-softmmu/panda-system-x86_64 -m 1G -replay " + (join("/transfer", replay_name + "-panda"))
        cmd += " -pandalog " + pandalog
        cmd += " -os linux-64-ubuntu:4.15.0-72-generic -panda file_taint:filename=" + input_basename 
        cmd += ",pos=1 -panda tainted_instr -panda tainted_branch"

        print("cmd = [%s]\n" % cmd)

        client.containers.run(cfg.taint.panda_container, cmd, volumes=volume_dict)

        log.info("Replay with taint completed")


if __name__ == "__main__":
    log.info("panda_taint.py started")
    run()
    log.info("panda_taint.py finished")
