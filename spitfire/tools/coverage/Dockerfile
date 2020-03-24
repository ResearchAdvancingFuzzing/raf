#FROM phusion/baseimage:master 
#FROM ubuntu:18.04 
FROM pandare/panda:latest 

#RUN apt-get update \
#    && apt-get -y upgrade -o Dpkg::Options::="--force-confold" \
#    && apt-get -y install ${image_extra_packages} \
#        libcapstone3 libdwarf1 libprotobuf10 libprotobuf-c1 \
#        $(apt-cache depends qemu-system-x86 | awk '/Depends:/{ print $2 }') \
#    && apt-get -y install libcapstone3 libdwarf1 libprotobuf10 libprotobuf-c1 \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/* \
#    && rm -rf /tmp/* /var/tmp/*

#RUN apt-get update -y 
#RUN apt-get -y install genisoimage libc6-dev-i386 gcc-multilib nasm 

#RUN apt-get install -y curl xxd python3.6 python3-pip libyaml-0-2 libyaml-dev 
RUN apt-get install -y python3.6 python3-pip vim libyaml-0-2 libyaml-dev
#wget docker git vim 

# Install python3 modules 
RUN pip3 install grpcio grpcio-tools hydra-core
RUN pip3 install pyyaml cffi colorama google-api-python-client protobuf

# Setup pypanda
WORKDIR /panda/panda/pypanda/
RUN python3.6 setup.py install 

# Get the qcow image; put it in the right place  
#WORKDIR /panda-replays/targets
RUN mkdir /qcows
WORKDIR /qcows 
RUN wget http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64.qcow2

# Get panda-replays directory 
#RUN git clone https://github.com/ResearchAdvancingFuzzing/panda-replays.git /panda-replays
#COPY spitfire/tools/taint/panda/panda-replays /panda-replays

#COPY /Users/he27553/Documents/raf/raf/spitfire/ /spitfire
#COPY spitfire/ /spitfire 

# Make the input directory (this will be something different later)  
#RUN mkdir /input
#RUN cp /panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit/inputs/attrib.xml /input/attrib.xml

# Get the qcow image; put it in the right place  
#WORKDIR /panda-replays/targets
#RUN mkdir /qcows
#WORKDIR /qcows #/panda-replays/targets/qcows
#RUN wget http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64.qcow2
#WORKDIR /panda-replays/targets
#RUN mkdir qcows && mv /bionic-server-cloudimg-amd64.qcow2 qcows  

#WORKDIR /
#RUN cp -r /panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit/ /replay 

#WORKDIR /
#WORKDIR /panda-source/panda/panda/pypanda/
#RUN ls 
#python3.6 setup.py install 

COPY ./infinite ./infinite 
COPY ./spitfire/tools/coverage/coverage.py ./
CMD ./infinite

#WORKDIR /spitfire/tools/taint/panda/

#WORKDIR /panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit
#CMD python3.6 ./run.py ./yamlfile /input/attrib.xml
#CMD python3.6 panda_taint.py 

 #panda_taint.py ./
#COPY taint_analysis.py ./  
#spitfire/tools/mutfuzz/script.sh ./
#COPY  
#CMD python3.6 panda_taint.py
