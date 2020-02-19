import sys, os, subprocess, glob

def run_drcov(directory):
    os.chdir(directory) 
    for filename in os.listdir(directory):
        if filename.endswith(".input"):
            # run drcov on the input
            drcov_args =  ['/dynamorio/build/bin64/drrun', '-t', 'drcov', '--', binary, '-c', 'jpeg', filename, '/dev/null']
            drcov_result = subprocess.call(drcov_args, stdout=sys.stdout, stderr=sys.stderr)
            #if drcov_result == 0: # then we have the .log file 
            base = os.path.splitext(filename)[0]
            for drcov_file in glob.glob("*.log"): #should only be one
                extension = ".coverage"
                output = os.rename(drcov_file, base + extension) 

        # rename the .log file to the first part of input + .coverage 

binary="/usr/local/bin/tiff2rgba" 
arguments="-c jpeg /fuzzing/interesting/crash/87b350d2.input  /dev/null" 
run_drcov("/interesting/crash")
run_drcov("/coverage")


