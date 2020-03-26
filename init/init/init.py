from kubernetes import client, utils, config
import os
import yaml
import time

def setup():
    config.load_incluster_config() 
    k8sClient = client.ApiClient()
    k8s_api = utils.create_from_yaml(k8sClient, "config_server.yaml")
    # Need to start up the fm

if __name__ == '__main__':
    setup()
