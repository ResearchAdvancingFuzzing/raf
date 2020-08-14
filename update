#!/bin/bash

# Exit if error
set -e

# Rebuild protos
cd spitfire/protos && make clean && make && cd ../..

# Rebuild docker images 
docker build -t init:v1 -f spitfire/init/Dockerfile_init .
docker build -t fm:v1 -f spitfire/fuzzing_manager/Dockerfile .
docker build -t gtfo-source:v1 -f spitfire/tools/gtfo-source/Dockerfile .
docker build -t seed-corpus:v1 -f spitfire/init/Dockerfile_corpus .
docker build -t target:xmllint -f spitfire/init/Dockerfile_target .
docker build -t spitfire:v1 .
docker build -t fuzzer:v1 -f spitfire/components/mutfuzz/Dockerfile .
docker build -t knowledge-base:v1 -f spitfire/knowledge_base/Dockerfile .
#docker build -t spitfirepanda -f ./Dockerfile_panda .
docker build -t taint:v1 -f spitfire/components/taint/panda/Dockerfile_taint .
docker build -t coverage:v1 -f spitfire/components/coverage/Dockerfile .

