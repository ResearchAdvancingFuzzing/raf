FROM ubuntu:18.04

RUN apt-get upgrade -y
RUN apt-get update -y
RUN apt-get install -y python3.6 python3-pip

RUN pip3 install --upgrade setuptools
RUN pip3 install requests
RUN pip3 install grpcio grpcio-tools hydra-core
RUN pip3 install pyyaml 
RUN pip3 install google-api-python-client protobuf 
RUN pip3 install google-auth

RUN apt-get install git vim -y

RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
RUN python3.6 setup.py install 

WORKDIR /
ENV SOURCE_DIR spitfire/fuzzing_manager
COPY $SOURCE_DIR/fm.py ./
COPY $SOURCE_DIR/jobs/config_taint.yaml ./
COPY $SOURCE_DIR/jobs/config_fuzzer.yaml ./
COPY $SOURCE_DIR/jobs/config_coverage.yaml ./
CMD python3.6 fm.py 

