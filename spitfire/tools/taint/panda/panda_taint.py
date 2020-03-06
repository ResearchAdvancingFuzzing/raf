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
from panda import Panda, blocking
from panda import * 

# Spitfire Directory
spitfire_dir="/spitfire" # Env variable
sys.path.append("/")
sys.path.append(spitfire_dir) # this will be an env at some point 
sys.path.append(spitfire_dir + "/protos")

assert (not (spitfire_dir is None)) 

import spitfire.protos.knowledge_base_pb2 as kbp 
import spitfire.protos.knowledge_base_pb2_grpc as kbpg
import knowledge_base
from google.protobuf import text_format 

# Qcow file
qcow = "http://panda-re.mit.edu/qcows/linux/ubuntu/1804/bionic-server-cloudimg-amd64.qcow2" # Config 
qcowfile = basename(qcow) 
qcf = "/panda-replays/targets/qcows/" + qcowfile 
assert(os.path.isfile(qcf))

# Target binary directory
installdir = "/install" # Env variable  
assert(os.path.isdir(installdir))

import shutil

log = logging.getLogger(__name__)

inputfile = os.environ.get('INPUT_FILE')
assert(os.path.exists(inputfile))
assert(os.path.isfile(inputfile))

# this should really be argv[1]
fuzzing_config_dir = "%s/config/expt1" % spitfire_dir  # Can you send this in as an argument? 


@hydra.main(config_path=fuzzing_config_dir + "/config.yaml")
def run(cfg):
    # print(cfg.pretty())
    
    # Get the input file 
    #inputfile = cfg.taint.input_file
    
    # channel to talk to kb server
    #with grpc.insecure_channel("%s:%s" % (cfg.knowledge_base.host, cfg.knowledge_base.port)) as channel:
    with grpc.insecure_channel('%s:%d' % ("10.105.43.27", 61111)) as channel:
    #with grpc.insecure_channel('%s:%d' % ("localhost", 61113)) as channel:

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

        print("input file is [%s]" % inputfile) #cfg.taint.input_file)
        input_msg = kbp.Input(filepath=inputfile) #cfg.taint.input_file)
        taint_input = kbs.AddInput(input_msg)

        # if we have already performed this taint analysis, bail
        taint_analysis_msg = kbp.Analysis(tool=panda.uuid, \
                                          target=target.uuid, \
                                          input=taint_input.uuid)
        taint_analysis = kbs.AddAnalysis(taint_analysis_msg)

        msg_end =  "\ntool[%s]\ntarget[%s]\ninput[%s]" \
                  % (text_format.MessageToString(panda), \
                     text_format.MessageToString(target), \
                     text_format.MessageToString(taint_input))

        if taint_analysis.complete:
            log.info("Taint analysis already performed for %s" % msg_end)
            return
        
        log.info("Taint analysis proceeding for %s" % msg_end)
        
        log.info("Creating recording")
        
        # Copy directory needed to insert into panda recording
        # We need the inputfile and we need the target binary install directory
        copydir = "./copydir"
        if os.path.exists(copydir):
            shutfil.rmtree(copydir)
        os.makedirs(copydir) 
        shutil.copy(inputfile, copydir)
        shutil.copytree(installdir, copydir + "/install") 


        # Create panda recording
        replaydir = "/replay"
        replayname = replaydir + basename(inputfile) + "-panda"
        print("replay name = [%s]" % replayname)

        cmd = "cd copydir/install/libxml2/.libs && ./xmllint ~/copydir/"+basename(inputfile)
        panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", qcow=qcf, mem="1G", extra_args="-display none -nographic") # -pandalog taint.plog")

        @blocking
        def take_recording():
            panda.record_cmd(cmd, copydir, recording_name=replayname)
            panda.stop_run()
 

        panda.queue_async(take_recording)
        panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
        panda.run()

        panda.set_pandalog("taint.plog")
        panda.load_plugin("osi")
        panda.load_plugin("osi_linux")
        panda.load_plugin("tainted_instr")
        panda.load_plugin("tainted_branch")
        panda.load_plugin("file_taint", args={"filename": "/root/copydir/"+basename(inputfile), "pos": "1"})

        panda.run_replay(replayname) 

        

if __name__ == "__main__":
    run()
    log.info("panda_taint.py finished")
