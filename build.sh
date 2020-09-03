#!/bin/bash

id=$1

if [ -z "$id" ]
then 
    echo "Usage: ./start.sh <campaign-id>"
    exit 1
fi
# Exit if error
set -e

# Rebuild protos
cd spitfire/protos && make clean && make && cd ../..

# Rebuild docker images 
docker build -t init:$id -f spitfire/init/Dockerfile_init .
docker build -t fm:$id -f spitfire/fuzzing_manager/Dockerfile .
docker build -t gtfo-source:v1 -f spitfire/tools/gtfo-source/Dockerfile .
docker build -t seed-corpus:$id -f spitfire/init/Dockerfile_corpus .
docker build -t target:$id -f spitfire/init/Dockerfile_target .
docker build -t spitfire:$id .
docker build -t fuzzer:$id -f spitfire/components/mutfuzz/Dockerfile .
docker build -t knowledge-base:$id -f spitfire/knowledge_base/Dockerfile .
#docker build -t spitfirepanda -f ./Dockerfile_panda .
docker build -t taint:$id -f spitfire/components/taint/panda/Dockerfile_taint .
docker build -t coverage:$id -f spitfire/components/coverage/Dockerfile .


python3.6 start.py campaign.id=$id
