#!/bin/bash

# Script to run gtfo and drcov and output .coverage files 

# This needs to be environment variables in the container not in here

extension="input"

run_drcov() {
    directory=$1
    cd $directory
    for fullfile in $directory/*.input; do
        # run drcov on fil
        $COVERAGE_DIR/dynamorio/build/bin64/drrun -t drcov -- \
            $TARGET_DIR/tiff2rgba -c jpeg $fullfile /dev/null #> /dev/null 2>&1
        # rename the log file to input .coverage file 
        filename=$(basename -- "$fullfile") 
        #extension="coverage" #"${filename##*.}"
        filename="${filename%.*}"
        new_filename="$filename.$extension"
        logfile=$(ls *.log)
        mv $logfile $new_filename
    done
}

cp ./drcov.py $SPITFIRE/tools/mutfuzz
mkdir $WORK_DIR 
cd $WORK_DIR 

LD_LIBRARY_PATH=$GTFO_DIR/gtfo/lib/ ANALYSIS_SIZE=65536 JIG_MAP_SIZE=65536 JIG_TARGET=$TARGET_DIR/tiff2rgba  JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null" $GTFO_DIR/gtfo/bin/the_fuzz -S $GTFO_DIR/gtfo/gtfo/analysis/afl_bitmap_analysis.so -O $GTFO_DIR/gtfo/gtfo/ooze/afl_havoc.so -J $GTFO_DIR/gtfo/gtfo/the_fuzz/afl_jig.so -i $CORPUS_DIR/not_kitty.tiff -n 1000 -x 1024 -c bitmap -s `head -c 10 /dev/urandom | xxd -p`

# For now lets just put it all into the inputs directory 
# We can separate later 
cp $WORK_DIR/interesting/crash/*.$extension /inputs
cp $WORK_DIR/coverage/*.$extension /inputs

run_drcov "$WORK_DIR/interesting/crash"
run_drcov "$WORK_DIR/coverage"

#while : 
#do 
#    sleep 1
#done
python3.6 $SPITFIRE/tools/mutfuzz/cov2api.py
