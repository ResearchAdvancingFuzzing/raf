#FROM pandare/panda:latest 
FROM spitfirepanda 

#RUN apt-get upgrade -y
#RUN apt-get update -y
RUN apt-get install -y python3.6 python3-pip vim libyaml-0-2 libyaml-dev

# Install python3 modules 
RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN pip3 install requests
RUN pip3 install grpcio grpcio-tools hydra-core
RUN pip3 install pyyaml cffi colorama 
RUN pip3 install google-api-python-client protobuf
RUN pip3 install google-auth
RUN pip3 install kubernetes

# Get the qcow image; put it in the right place  
RUN mkdir /qcows
WORKDIR /qcows 
RUN wget http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64.qcow2

# Setup pypanda
WORKDIR /panda/panda/python/core/
RUN python3.6 setup.py install 

# Setup kubernetes client 
#RUN pip3 install --upgrade setuptools
#RUN pip3 install requests
#RUN git clone --recursive https://github.com/kubernetes-client/python.git
#WORKDIR python
#RUN python3.6 setup.py install 

WORKDIR /
RUN mkdir working
WORKDIR working
COPY ./infinite ./infinite 
COPY ./spitfire/components/coverage/run.py ./

