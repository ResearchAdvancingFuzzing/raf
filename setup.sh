#!/bin/bash

# exit when any command fails
set -e 

# clone gtfo
gtfo_dir=spitfire/tools/gtfo-source/gtfo
if [[ -d "$gtfo_dir" ]]
then 
    echo "Error: $gtfo_dir already exists." 
    exit 1
else
    git clone https://github.com/ResearchAdvancingFuzzing/gtfo.git $gtfo_dir
fi

# clone a seed corpus
git clone https://github.com/ResearchAdvancingFuzzing/panda-replays.git spitfire/init/panda-replays
mv spitfire/init/panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit/inputs spitfire/init/corpus

# make our proto files 
cd spitfire/protos && make && cd ../..

# build all of our images
docker build -t init:v1 -f spitfire/init/Dockerfile_init .
docker build -t fm:v1 -f spitfire/fuzzing_manager/Dockerfile .
docker build -t gtfo-source:v1 -f spitfire/tools/gtfo-source/Dockerfile .
docker build -t seed-corpus:v1 -f spitfire/init/Dockerfile_corpus .
docker build -t target:xmllint -f spitfire/init/Dockerfile_target .
docker build -t spitfire:v1 .
docker build -t fuzzer:v1 -f spitfire/components/mutfuzz/Dockerfile .
docker build -t knowledge-base:v1 -f spitfire/knowledge_base/Dockerfile .
docker build -t spitfirepanda -f ./Dockerfile_panda .
docker build -t taint:v1 -f spitfire/components/taint/panda/Dockerfile_taint .
docker build -t coverage:v1 -f spitfire/components/coverage/Dockerfile .
