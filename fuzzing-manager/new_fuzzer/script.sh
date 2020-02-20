#!/bin/bash

export WORK_DIR="/gtfo-source" #"/home/he27553" #"/gtfo-source"
export TARGET_DIR="/target" #"/usr/local/bin" #"/target"
export CORPUS_DIR="/seed-corpus"
export COVERAGE_DIR="/coverage" #"/home/he27553" #"/coverage"
export SPITFIRE="/spitfire" #"/spitfire"

run_drcov() {
    directory=$1
    cd $directory
    for fullfile in $directory/*.input; do
        # run drcov on fil
        $COVERAGE_DIR/dynamorio/build/bin64/drrun -t drcov -- \
            $TARGET_DIR/tiff2rgba -c jpeg $fullfile /dev/null #> /dev/null 2>&1
        # rename the log file to input .coverage file 
        filename=$(basename -- "$fullfile") 
        extension="coverage" #"${filename##*.}"
        filename="${filename%.*}"
        new_filename="$filename.$extension"
        logfile=$(ls *.log)
        mv $logfile $new_filename
    done
}

mkdir /python
cd /python
LD_LIBRARY_PATH=$WORK_DIR/gtfo/lib/ ANALYSIS_SIZE=65536 JIG_MAP_SIZE=65536 JIG_TARGET=$TARGET_DIR/tiff2rgba  JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null" $WORK_DIR/gtfo/bin/the_fuzz -S $WORK_DIR/gtfo/gtfo/analysis/afl_bitmap_analysis.so -O $WORK_DIR/gtfo/gtfo/ooze/afl_havoc.so -J $WORK_DIR/gtfo/gtfo/the_fuzz/afl_jig.so -i $CORPUS_DIR/not_kitty.tiff -n 1000 -x 1024 -c bitmap -s `head -c 10 /dev/urandom | xxd -p`


#echo "here"
#ls $WORK_DIR
#ls $TARGET_DIR
#ls $CORPUS_DIR
#ls $COVERAGE_DIR
#ls $SOURCE_DIR
#ls $WORK_DIR/interesting/crash
#echo "HEATHER COVERAGE"
#ls $WORK_DIR/coverage

#cd "$WORK_DIR/help"
# need to cd into proper directory 
#run_drcov "$WORK_DIR/help"
#run_drcov "$WORK_DIR/coverage"
#cd "$WORK_DIR/interesting/crash"
#cd $WORK_DIR/interesting/crash
run_drcov "/python/interesting/crash"
#ls $WORK_DIR/interesting/crash
run_drcov "/python/coverage"
#cd $WORK_DIR/coverage
#ls /python
#ls $WORK_DIR/coverage

#ls $SPITFIRE/tools/mutfuzz/cov2api.py

#while : 
#do 
#    sleep 1
#done
python3.6 $SPITFIRE/tools/mutfuzz/cov2api.py

#curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
#patch drcov.py < drcov.py.patch  
