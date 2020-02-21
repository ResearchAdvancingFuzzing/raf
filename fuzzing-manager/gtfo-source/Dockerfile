FROM ubuntu:18.04
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y clang wget xxd build-essential python cmake python-pip pkg-config python-yaml libyaml-0-2 libyaml-dev systemd --fix-missing
#RUN apt-get install -y git

WORKDIR /fuzzing/
# this will need to be a git clone at some point
#RUN git clone https://github.com/ResearchAdvancingFuzzing/gtfo.git /fuzzing/
COPY gtfo/ /fuzzing/ 
RUN mkdir -p build/ooze build/the_fuzz gtfo
WORKDIR /fuzzing/build/ooze
RUN CC=clang cmake -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../ooze/
RUN make
RUN make install
WORKDIR /fuzzing/build/the_fuzz
RUN CC=clang cmake -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../the_fuzz/
RUN make
RUN make install
WORKDIR /fuzzing/

CMD cp -r /fuzzing/gtfo/  /gtfo-source
#/shared/gtfo
#${GTFO_DIR}
#/gtfo-source
# target needs to be replaced with an env variable and a config map
