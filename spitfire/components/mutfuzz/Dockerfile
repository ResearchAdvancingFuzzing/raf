#FROM ubuntu:18.04
FROM gtfo-source:v1
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y curl xxd python3.6 python3-pip libyaml-0-2 libyaml-dev 
RUN pip3 install grpcio grpcio-tools hydra-core
RUN apt-get update -y
RUN apt-get install -y vim

# Setup kubernetes client 
RUN pip3 install --upgrade setuptools
RUN pip3 install requests
RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
RUN python3.6 setup.py install 

COPY spitfire/components/mutfuzz/run.py ./
COPY infinite ./
