#FROM pandare/panda:latest 
FROM spitfirepanda:python 

WORKDIR /panda/panda/python/core 
RUN python3.6 setup.py install 

FROM raf:latest 
# Install dependencies 
RUN apt-get update \
    && apt-get -y upgrade -o Dpkg::Options::="--force-confold" \
    && apt-get -y install ${image_extra_packages} \
        libcapstone3 libdwarf1 libprotobuf10 libprotobuf-c1 \
        python3.6 python3-pip vim libyaml-0-2 libyaml-dev genisoimage \
        $(apt-cache depends qemu-system-x86 | awk '/Depends:/{ print $2 }') \
    && apt-get -y install libcapstone3 libdwarf1 libprotobuf10 libprotobuf-c1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

# Take minimal set of panda files we need
RUN mkdir -p /usr/local/lib/python3.6/dist-packages/panda /panda/build/x86_64-softmmu /panda/pc-bios /panda/build/pc-bios 
COPY --from=0 /usr/local/lib/python3.6/dist-packages/panda /usr/local/lib/python3.6/dist-packages/panda
COPY --from=0 /panda/build/x86_64-softmmu /panda/build/x86_64-softmmu
COPY --from=0 /panda/build/pc-bios/ /panda/build/pc-bios
COPY --from=0 /panda/pc-bios /panda/pc-bios


WORKDIR /
RUN mkdir target replays
#COPY slashdot/xmllint /target/xmllint
#COPY slashdot/slashdot.xml slashdot.xml
#COPY slashdot/script.py script.py
COPY ./infinite ./infinite 
COPY ./spitfire/components/coverage/run.py ./

