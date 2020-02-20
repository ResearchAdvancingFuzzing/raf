FROM ubuntu:18.04 
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install -y git cmake gcc g++ python
RUN git clone https://github.com/DynamoRIO/dynamorio.git /dynamorio
WORKDIR dynamorio
RUN mkdir build 
WORKDIR build
RUN cmake .. 
RUN make -j

CMD cp -r /dynamorio /coverage
