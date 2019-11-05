# This needs to be a Job that basically sets up the database with the correct tables
# since we are using SQLalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Date, create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from kubernetes import client, config
import base64
import os
import yaml

Base = declarative_base()

class Book(Base):
    __tablename__ = 'books'
    id = Column(Integer, primary_key=True)
    title = Column(String)
    author = Column(String)
    pages = Column(Integer)
    published = Column(Date)

def recreate_database(engine):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

# Default values
namespace = 'default'
database_name = 'postgres'
username = 'postgres'


def setup():
    # Internal
    config.load_incluster_config()

    # External
    # config.load_kube_config()

    v1 = client.CoreV1Api()

    # Get the username and database_name
    for dic in v1.list_namespaced_pod(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.containers[0].env:
        if dic.name == "POSTGRES_USER":
            username = dic.value
        if dic.name == "POSTGRES_DB":
            database_name = dic.value

    # External -- if its a NodePort service; this is just used for testing purposes
    node_ip = str(v1.list_node().items[0].status.addresses[0].address)
    node_port = str(v1.list_namespaced_service(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.ports[0].node_port)

    # Internal -- if its a ClusterIP service
    ip = str(v1.list_namespaced_service(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.cluster_ip)
    port = str(v1.list_namespaced_service(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.ports[0].port)

    password = v1.list_namespaced_secret(namespace='default', label_selector="app=postgresql").items[0].data["postgresql-password"]
    password = base64.b64decode(password).decode('ascii')

    DATABASE_URI="postgresql+psycopg2://{}:{}@{}:{}/{}".format(username, password, ip, port, database_name)
    print(DATABASE_URI)
    # what is should be: DATABASE_URI = "postgresql+psycopg2://postgres:postgres@192.168.99.103:30651/books"

    engine = create_engine(DATABASE_URI)
    Base.metadata.create_all(engine)
    print("made it to the end without crashing")
    # \dt in the postgres database should show that the tables are here


setup()
