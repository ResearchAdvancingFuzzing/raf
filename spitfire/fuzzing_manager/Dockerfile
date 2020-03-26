FROM python:3.6 

RUN pip install psycopg2
RUN pip install requests

RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
RUN python setup.py install 

COPY spitfire/fuzzing-manager/fm.py ./
COPY config_taint.yaml ./
COPY config_fuzzer.yaml ./
COPY config_coverage.yaml ./

CMD python3.6 fm.py

