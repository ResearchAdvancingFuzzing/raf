FROM ubuntu:18.04
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y curl xxd python3.6 python3-pip libyaml-0-2 libyaml-dev 
#RUN apt-get install -y xxd build-essential python python3.6 python3-pip cmake python-pip pkg-config python-yaml libyaml-0-2 libyaml-dev systemd --fix-missing 
#curl python3.6
#RUN apt-get install -y curl --fix-missing
#RUN pip3 install grpcio grpcio-tools hydra-core

# RUN AS INITCONTAINER
#COPY drcov.py.patch ./
#RUN curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
#RUN patch drcov.py < drcov.py.patch  

# This is the script to run both the fuzzer and drcov after 
#COPY script.sh /

#CMD ["./script.sh"]

# Okay some stuff can stay and some stuff needs to be moved; 
# Environment setup needs to leave; we need to create a docker image with all of the wgets for afl, libtiff, gtfo, and curls ahead of time; the image should have all environment stuff already 

# Then in here we need to actually run the fuzzer in the already curated docker image and 
#ENV WORK_DIR /gtfo-source 
#ENV TARGET_DIR /target
#ENV CORPUS_DIR /seed-corpus
#ENV COVERAGE_DIR /coverage
#ENV SOURCE_DIR /spitfire 

#COPY script.sh /

# Run the fuzzer; all of this needs to be parametrized! 
#RUN LD_LIBRARY_PATH=$WORK_DIR/gtfo/lib/ ANALYSIS_SIZE=65536 JIG_MAP_SIZE=65536 JIG_TARGET=$TARGET_DIR/tiff2rgba  JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null" $WORK_DIR/gtfo/bin/the_fuzz -S $WORK_DIR/gtfo/gtfo/analysis/afl_bitmap_analysis.so -O $WORK_DIR/gtfo/gtfo/ooze/afl_havoc.so -J $WORK_DIR/gtfo/gtfo/the_fuzz/afl_jig.so -i $SEED_CORPUS/not_kitty.tiff -n 1000 -x 1024 -c bitmap -s `head -c 10 /dev/urandom | xxd -p`

# After this runs we have interesting/crash and coverage within $WORK_DIR 
 
#COPY --from=0 /fuzzing/interesting/crash /interesting/crash
#COPY --from=0 /fuzzing/coverage /coverage
#COPY --from=0 /usr/local/bin/tiff2rgba /usr/local/bin/tiff2rgba
# Now we need to run each .input file with drcov
#WORKDIR $WORK_DIR/coverage
# Prob can write this script not in python
#RUN python /script.py
#WORKDIR /interesting/crash
#RUN python /script.py

#RUN apt-get install -y curl
#WORKDIR /
#COPY drcov.py.patch ./
#RUN curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
#RUN patch drcov.py < drcov.py.patch  

# We need to the grpc client part; we need to copy in the entire spitfire directory
#FROM python:3.6
#RUN apt-get install -y xxd --fix-missing

COPY drcov.py.patch ./
RUN curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
RUN patch drcov.py < drcov.py.patch  

RUN pip3 install grpcio grpcio-tools hydra-core

COPY script.sh ./

CMD ["./script.sh"]

#WORKDIR python
#COPY --from=1 /coverage ./coverage
#COPY ./spitfire/ ./spitfire

#CMD python3.6 spitfire/tools/mutfuzz/cov2api.py
