#FROM ubuntu:18.04
FROM gtfo-source:v1

RUN apt-get upgrade -y
RUN apt-get update -y

RUN apt-get install -y curl xxd
RUN apt-get install -y libyaml-0-2 libyaml-dev

RUN apt-get install -y --fix-missing python3.6 python3-pip 
RUN pip3 install --upgrade pip 
RUN pip3 install --upgrade setuptools
RUN pip3 install requests
RUN pip3 install grpcio grpcio-tools hydra-core
RUN pip3 install pyyaml 
RUN pip3 install google-api-python-client protobuf
RUN pip3 install google-auth
RUN pip3 install kubernetes

COPY spitfire/components/mutfuzz/run.py ./
COPY infinite ./
