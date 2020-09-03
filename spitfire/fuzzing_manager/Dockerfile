FROM ubuntu:18.04

RUN apt-get upgrade -y
RUN apt-get update -y
RUN apt-get install -y python3.6 python3-pip

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN pip3 install requests
RUN pip3 install grpcio grpcio-tools hydra-core
RUN pip3 install pyyaml 
RUN pip3 install google-api-python-client protobuf 
RUN pip3 install google-auth
RUN pip3 install kubernetes 

RUN apt-get install git vim -y

WORKDIR /
ENV SOURCE_DIR spitfire/fuzzing_manager
COPY $SOURCE_DIR/spitfire.py ./
COPY infinite ./
#CMD ./infinite
CMD python3.6 spitfire.py 
