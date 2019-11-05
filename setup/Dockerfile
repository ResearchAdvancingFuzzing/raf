FROM python:3

RUN pip install sqlalchemy
RUN pip install psycopg2
RUN pip install requests

RUN git clone --recursive https://github.com/kubernetes-client/python.git
WORKDIR python
RUN python setup.py install

COPY setup_db.py ./

CMD python setup_db.py
