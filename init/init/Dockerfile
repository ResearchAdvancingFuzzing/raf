FROM python:3.6 

RUN pip install psycopg2
RUN pip install requests

RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
RUN python setup.py install 

COPY init/init/init.py ./
COPY config_server.yaml ./
CMD python3.6 init.py 

#FROM ubuntu
#CMD echo "Target Regular:" && ls /target && echo "Seed Corpus:" && ls /seed-corpus && echo "Spitfire: " && ls /spitfire 
#CMD echo "hi" && ls $SHARED_DIR && echo "AFTER" && $TARGET_DIR && ls $GTFO_DIR && echo "seed" && ls $CORPUS_DIR && echo "spittttfire: " && ls $SPITFIRE && echo "coverage" && ls $COVERAGE_DIR
