FROM python:3

RUN pip install requests

RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
RUN python setup.py install

COPY fm.py ./

CMD python fm.py
