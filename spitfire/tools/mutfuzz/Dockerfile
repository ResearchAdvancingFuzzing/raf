FROM ubuntu:18.04
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y curl xxd python3.6 python3-pip libyaml-0-2 libyaml-dev 

COPY spitfire/tools/mutfuzz/drcov.py.patch ./
RUN curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py 
RUN patch drcov.py < drcov.py.patch  

RUN pip3 install grpcio grpcio-tools hydra-core

COPY spitfire/tools/mutfuzz/script.sh ./

CMD ["./script.sh"]

