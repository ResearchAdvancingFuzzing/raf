#!/bin/bash
id=$1

echo "Namespace for the campaign: $id"

set -e

# Rebuild protos
cd spitfire/protos && make clean && make && cd ../..

# Rebuild docker images 
#docker build -t gtfo-source:v1 -f spitfire/tools/gtfo-source/Dockerfile .
#docker build -t spitfirepanda:python -f ./Dockerfile_panda .
#docker build -t raf -f ./Dockerfile_raf . 

docker build -t init:$id -f spitfire/init/Dockerfile_init .
docker build -t fm:$id -f spitfire/fuzzing_manager/Dockerfile .
docker build -t seed-corpus:$id -f spitfire/init/Dockerfile_corpus .
docker build -t target:$id -f spitfire/init/Dockerfile_target .
docker build -t spitfire:$id .
docker build -t fuzzer:$id -f spitfire/components/fuzzer/Dockerfile .
docker build -t knowledge-base:$id -f spitfire/knowledge_base/Dockerfile .
docker build -t taint:$id -f spitfire/components/taint/panda/Dockerfile_taint .
docker build -t coverage:$id -f spitfire/components/coverage/Dockerfile .

python3.6 start.py campaign.id=$id

echo 
echo "RAF campaign started.  Namespace $id"
