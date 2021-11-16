FROM gtfo-source:v1

FROM raf:latest 
RUN mkdir /gtfo
COPY --from=0 /gtfo /gtfo

# Dependencies to run GTFO 
RUN apt-get upgrade -y && apt-get update -y && apt-get install -y curl xxd libyaml-0-2 libyaml-dev python3.6 python3-pip 

COPY spitfire/components/fuzzer/run.py ./
COPY infinite ./
