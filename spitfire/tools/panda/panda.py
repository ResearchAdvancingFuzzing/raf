import logging 
import shutil
from panda import Panda, blocking
from panda import *

class PandaTarget:
    def __init__(self, target, input_file, plog_file_name, qcow):
        self.target = target
        self.input = input_file
        self.plog_file_name = plog_file_name
        self.replay_name =  "%s/%s" % (replay_dir, basename(input_file) + "-panda") 
        self.panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", 
                qcow=qcow, mem="1G", extra_args="-display none -nographic") 
        self.panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
        self.asids = []
        self.modules = []

    def create_recording(self): 
        log.info("Creating recording")

        # Copy directory needed to insert into panda recording
        # We need the inputfile and we need the target binary install directory
        copydir = "./copydir"
        if os.path.exists(copydir):
            shutfil.rmtree(copydir)
        os.makedirs(copydir) 
        shutil.copy(input_file, copydir)
        shutil.copytree(target_dir, copydir + "/install") 

        # Get the qcow file 
        qcowfile = basename(self.qcow)
        qcf = "/qcows/%s" % qcowfile 
        assert(os.path.isfile(qcf))

        # Create panda recording
        print("replay name = [%s]" % self.replay_name)

        # This needs to be changed
        cmd = "cd copydir/install/ && ./%s ~/copydir/%s" % (self.target, basename(self.input)
        #print(cmd) 
        #cmd = "cd copydir/install/libxml2/.libs && ./xmllint ~/copydir/"+basename(inputfile)
        #print(cmd) 
        #return
        #panda = Panda(arch="x86_64", expect_prompt=rb"root@ubuntu:.*#", 
        #        qcow=qcf, mem="1G", extra_args="-display none -nographic") 

        @blocking
        def take_recording():
            self.panda.record_cmd(cmd, copydir, recording_name=self.replay_name)
            self.panda.stop_run()


        self.panda.queue_async(take_recording)
        self.panda.run()

    def run_replay(self, plugins): 
        # Now insert the plugins and run the replay
        self.panda.set_pandalog(self.plog_file_name)
        for plugin_name in plugins:
            self.panda.load_plugin(plugin_name, plugins[plugin_name])
        self.panda.run_replay(self.replay_name)

    
    def get_asids(self): 
        if 
        '''
        self.panda.load_plugin("osi")
        self.panda.load_plugin("osi_linux")
        self.panda.load_plugin("tainted_instr")
        self.panda.load_plugin("asidstory")
        self.panda.load_plugin("collect_code")
        self.panda.load_plugin("tainted_branch")
        self.panda.load_plugin("file_taint", 
                args={"filename": "/root/copydir/"+basename(self.input_file), "pos": "1"})
        self.panda.load_plugin("edge_coverage")
        self.panda.load_plugin("loaded_libs")
        self.panda.run_replay(self.replay_name) 
        '''


