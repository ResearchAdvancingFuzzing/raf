#!/bin/bash

commit=$(git rev-parse HEAD | cut -c 1-8)
tag=$(git describe --exact-match --tags $commit) 

if [ -z "$commit" ] 
then
   echo "git commit is empty" 
   exit 1
elif [ -z "$tag" ]
then
   echo "The current git commit is not tagged. Please tag using git tag and then try again." 
   exit 1
fi

base_id="$commit$tag"

# Check for the largest version number for this id currently used and increment it
num="$(($(kubectl get namespaces | awk '{print $1}' | grep "$base_id" | sed -e "s/$base_id//" | sort | sed '$!d') + 1 ))"
id="$base_id$num"

echo "Namespace for the campaign: $id"

set -e

# Rebuild protos
cd spitfire/protos && make clean && make && cd ../..

# Rebuild docker images 
docker build -t gtfo-source:v1 -f spitfire/tools/gtfo-source/Dockerfile .
#docker build -t spitfirepanda -f ./Dockerfile_panda .
docker build -t spitfirepanda:python -f ./Dockerfile_18_04 .
docker build -t raf -f ./Dockerfile_raf . 

docker build -t init:$id -f spitfire/init/Dockerfile_init .
docker build -t fm:$id -f spitfire/fuzzing_manager/Dockerfile .
docker build -t seed-corpus:$id -f spitfire/init/Dockerfile_corpus .
docker build -t target:$id -f spitfire/init/Dockerfile_target .
docker build -t spitfire:$id .
docker build -t fuzzer:$id -f spitfire/components/mutfuzz/Dockerfile .
docker build -t knowledge-base:$id -f spitfire/knowledge_base/Dockerfile .
docker build -t taint:$id -f spitfire/components/taint/panda/Dockerfile_taint .
docker build -t coverage:$id -f spitfire/components/coverage/Dockerfile .

python3.6 start.py campaign.id=$id
