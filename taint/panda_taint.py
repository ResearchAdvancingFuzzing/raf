
"""

Create recording.  Run replay with taint analysis.  Ingest results to knowledge base

"""

import sys
import docker
import spitfire.knowledge_base as kb

client = docker.from_env()


# NB: all of these should come from config
panda_container_name = "panda_spitfire"
panda_binary = "panda/build/i386-softmmu/panda-system-i386"
panda_install_string = "git clone -b spitfire_0 https://github.com/panda-re/panda.git"
program_fn = "/fs/programs/file-32"
input_fn = "/fs/inputs/file-32/

# these are protobuf msg? 
taint_engine = kb.get_taint_engine(panda_install_string)
program = kb.get_program(program_fn)
input = kb.get_input(inpuf_fn)

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
    input_msg = kb_stub.GetInput(im)
    
    

cmd = "panda/panda/scripts/run_debian.py " + program + " " + input + " && " + panda_binary " + ftmmu/panda-system-i386 -replay replays/toy/toy -os linux-32-debian:3.2.0-4-686-pae -pandalog /transfer/toy.plog -panda file_taint:filename=testsmall.bin,pos=1 -panda tainted_branch && panda/panda/scripts/plog_reader.py /transfer/toy.plog > /transfer/toy.plog.txt

client.containers.run(panda_container_name, "panda/panda/scripts/run_debian.py /transfer/toy /transfer/testsmall.bin && panda/build/i386-softmmu/panda-system-i386 -replay replays/toy/toy -os linux-32-debian:3.2.0-4-686-pae -pandalog /transfer/toy.plog -panda file_taint:filename=testsmall.bin,pos=1 -panda tainted_branch && panda/panda/scripts/plog_reader.py /transfer/toy.plog > /transfer/toy.plog.txt


# japan 
