FROM python:3.6


RUN python3.6 -m pip install grpcio grpcio-tools hydra-core
 
WORKDIR python


RUN mkdir knowledge_base
COPY spitfire/protos/* ./
COPY spitfire/knowledge_base/* ./
CMD python3.6 knowledge_base.py
