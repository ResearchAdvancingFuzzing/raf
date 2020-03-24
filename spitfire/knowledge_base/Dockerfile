FROM python:3.6

#RUN pip install requests

RUN python3.6 -m pip install grpcio grpcio-tools hydra-core
 
#RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
#RUN python setup.py install

#COPY ./spitfire/ ./spitfire
#COPY knowledge_base_test.py ./

#CMD ls 
RUN mkdir knowledge_base
COPY spitfire/protos/* ./
COPY spitfire/knowledge_base/* ./
#RUN python3.6 knowledge_base.py
CMD python3.6 knowledge_base.py
#CMD python3.6 /spitfire/knowledge_base/knowledge_base.py
