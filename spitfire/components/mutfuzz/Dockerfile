#FROM ubuntu:18.04
FROM gtfo-source:v1
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y curl xxd python3.6 python3-pip libyaml-0-2 libyaml-dev 
RUN pip3 install grpcio grpcio-tools hydra-core
RUN apt-get update -y
RUN apt-get install -y vim
COPY spitfire/components/mutfuzz/run.py ./
COPY infinite ./
