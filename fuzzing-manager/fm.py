#import kubernetes
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Date, create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from kubernetes import client
import base64
import os
import yaml

config.load_incluster_config()

v1 = client.CoreV1Api()
print("Listing pods with their IPs:")
ret = v1.list_pod_for_all_namespaces(watch=False)
for i in ret.items:
    print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))

configuration = client.Configuration()
configuration.api_key['authorization'] = 'YOUR_API_KEY'
api_instance = client.CoreV1Api(client.ApiClient(configuration))

namespace = 'default'
database_name = 'books'
username = 'postgres'

# External -- if its a NodePort service
node_ip = str(v1.list_node().items[0].status.addresses[0].address)
node_port = str(v1.list_namespaced_service(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.ports[0].node_port)

# Internal -- if its a ClusterIP service
ip = str(v1.list_namespaced_service(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.cluster_ip)
port = str(v1.list_namespaced_service(namespace=namespace, label_selector='app=postgresql', watch=False).items[0].spec.ports[0].port)

password = v1.list_namespaced_secret(namespace='default', label_selector="app=postgresql").items[0].data["postgresql-password"]
password = base64.b64decode(password).decode('ascii')
DATABASE_URI="postgresql+psycopg2://{}:{}@{}:{}/{}".format(username, password, node_ip, node_port, database_name)
# what is should be: DATABASE_URI = "postgresql+psycopg2://postgres:postgres@192.168.99.103:30651/books"



# with open("/transfer/fm.log", "w") as f:
#    f.write("Hello from fm.py\n")
