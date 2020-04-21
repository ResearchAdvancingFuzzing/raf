FROM pandare/panda:latest 

RUN apt-get install -y python3.6 python3-pip vim libyaml-0-2 libyaml-dev

# Install python3 modules 
RUN pip3 install grpcio grpcio-tools hydra-core
RUN pip3 install pyyaml cffi colorama google-api-python-client protobuf

# Get the qcow image; put it in the right place  
RUN mkdir /qcows
WORKDIR /qcows 
RUN wget http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64.qcow2

# Setup pypanda
WORKDIR /panda/panda/python/core/
RUN python3.6 setup.py install 

WORKDIR /
RUN mkdir working
WORKDIR working
COPY ./infinite ./infinite 
COPY ./spitfire/components/coverage/run.py ./

