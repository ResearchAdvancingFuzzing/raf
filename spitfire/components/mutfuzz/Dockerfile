FROM ubuntu:18.04
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y curl xxd python3.6 python3-pip libyaml-0-2 libyaml-dev 

#COPY spitfire/tools/mutfuzz/drcov.py.patch ./
#RUN curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
#RUN patch drcov.py < drcov.py.patch  


RUN pip3 install grpcio grpcio-tools hydra-core
#RUN pip3 install hydra-corei
RUN apt-get update -y
RUN apt-get install -y vim
COPY spitfire/components/mutfuzz/run_fuzzer.py ./
COPY infinite ./

#CMD ./script.sh
CMD ./infinite 
#./script.sh
#./infinite 
#["./script.sh"]

