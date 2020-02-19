FROM ubuntu:18.04
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y clang wget xxd build-essential python cmake python-pip pkg-config python-yaml libyaml-0-2 libyaml-dev systemd --fix-missing

# Okay some stuff can stay and some stuff needs to be moved; 
# Environment setup needs to leave; we need to create a docker image with all of the wgets for afl, libtiff, gtfo, and curls ahead of time; the image should have all environment stuff already 

# Then in here we need to actually run the fuzzer in the already curated docker image and 
WORKDIR /fuzzing
# This if for libtiff program and afl instrumentation
RUN mkdir libtiff_working
WORKDIR /fuzzing/libtiff_working
RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz
RUN wget https://download.osgeo.org/libtiff/old/tiff-3.7.0.tar.gz
RUN  tar xvf afl-2.52b.tgz
RUN  tar xvf tiff-3.7.0.tar.gz
RUN rm afl-2.52b.tgz
RUN rm tiff-3.7.0.tar.gz
WORKDIR /fuzzing/libtiff_working/afl-2.52b
RUN make
WORKDIR /fuzzing/libtiff_working/tiff-3.7.0
RUN CFLAGS="-static -fno-PIE -fno-PIC" CC=/fuzzing/libtiff_working/afl-2.52b/afl-clang ./configure --enable-shared=no
RUN CFLAGS="-static -fno-PIE -fno-PIC" CC=/fuzzing/libtiff_working/afl-2.52b/afl-clang make
RUN make install

#This is for the actual fuzzer but this will be moved out later 
WORKDIR /fuzzing/
COPY gtfo/ /fuzzing/
RUN mkdir -p build/ooze build/the_fuzz gtfo
WORKDIR /fuzzing/build/ooze
RUN CC=clang cmake -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../ooze/
RUN make
RUN make install
WORKDIR /fuzzing/build/the_fuzz
RUN CC=clang cmake -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../the_fuzz/
RUN make
RUN make install
WORKDIR /fuzzing/
ENV WORK_DIR /fuzzing
# Run the fuzzer; all of this needs to be parametrized! 
RUN LD_LIBRARY_PATH=$WORK_DIR/gtfo/lib/ ANALYSIS_SIZE=65536 JIG_MAP_SIZE=65536 JIG_TARGET=/usr/local/bin/tiff2rgba  JIG_TARGET_ARGV="-c jpeg fuzzfile /dev/null" $WORK_DIR/gtfo/bin/the_fuzz -S $WORK_DIR/gtfo/gtfo/analysis/afl_bitmap_analysis.so -O $WORK_DIR/gtfo/gtfo/ooze/afl_havoc.so -J $WORK_DIR/gtfo/gtfo/the_fuzz/afl_jig.so -i $WORK_DIR/libtiff_working/afl-2.52b/testcases/images/tiff/not_kitty.tiff -n 1000 -x 1024 -c bitmap -s `head -c 10 /dev/urandom | xxd -p`


# Now here we start our second stage of the multi-stage docker file and ONLY keep the two directories: 
# interesting/crash and coverage
 
FROM ubuntu:18.04 
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install -y git cmake gcc g++ python
RUN git clone https://github.com/DynamoRIO/dynamorio.git /dynamorio
WORKDIR dynamorio
RUN mkdir build 
WORKDIR build
RUN cmake .. 
RUN make -j
COPY --from=0 /fuzzing/interesting/crash /interesting/crash
COPY --from=0 /fuzzing/coverage /coverage
COPY --from=0 /usr/local/bin/tiff2rgba /usr/local/bin/tiff2rgba
COPY script.py /
# Now we need to run each .input file with drcov
WORKDIR /coverage
# Prob can write this script not in python
RUN python /script.py
WORKDIR /interesting/crash
RUN python /script.py

RUN apt-get install -y curl
WORKDIR /
COPY drcov.py.patch ./
RUN curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
RUN patch drcov.py < drcov.py.patch  

# We need to the grpc client part; we need to copy in the entire spitfire directory
FROM python:3.6

RUN python3.6 -m pip install grpcio grpcio-tools hydra-core
 
WORKDIR python
COPY --from=1 /coverage ./coverage
COPY ./spitfire/ ./spitfire

CMD python3.6 spitfire/tools/mutfuzz/cov2api.py
