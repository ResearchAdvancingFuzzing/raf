# RAF Setup

## Installation: 
Follow the instructions at https://kubernetes.io/docs/tasks/tools/install-minikube/ to install minikube and kubectl. The instructions to install minikube and kubectl for linux are reproduced below for convenience: 
```
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 \
  && chmod +x minikube
sudo mkdir -p /usr/local/bin/
sudo install minikube /usr/local/bin/

sudo apt-get update && sudo apt-get install -y apt-transport-https gnupg2
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubectl
```
## Setup Env: 
#### Python/Docker setup
On your host computer, you need to have python (version 3.6 or above), pip, and docker already installed. 
```
sudo apt-get install python3.6 python3-pip conntrack docker.io
sudo groupadd docker # Note this group may already be added; that is ok
sudo usermod -aG docker $USER 
```
**NOTE**: You need to log out and log back in for the docker permissions to take effect.

You then need to install the the following python packages in order to make the grpcio python files from the .proto file in the run script and to start and run a campaign. This assumes you want to use a python virtualenv.
```
$ python3 -m venv venv
$ . venv/bin/activate
(venv) $ python3 -m pip install wheel grpcio grpcio-tools hydra-core numpy kubernetes
```
#### Minikube setup
Instructions to setup a single-node Kubernetes cluster with minikube can be found at https://minikube.sigs.k8s.io/docs/. There are a few ways to do this (through docker, virtual machine, host, etc.) The instructions for starting the cluster from **docker** are reproduced below for convience:
```
minikube start --driver=docker
eval $(minikube docker-env)
```
**NOTE**: Running minikube with root user is not allowed here.
#### Minikube clean up
To delete the cluster created, run
```
minikube delete
```
## Setup RAF directory:
After cloning this repository, run the `setup.sh` script in order to pull the gtfo repo. 
```
git clone <this_repo> 
cd raf
./setup.sh 
```
Note: Run this only once, when you have a **clean** clone of the RAF repo. In this script, there is a clone of a repo to copy in a sample seed corpus into the `spitfire/init/corpus` directory. You may also provide your own seeds in that directory. 
## Building and running a campaign 
After initial setup, you can now either (1) run an already existing experiment in RAF or (2) create your own experiment. When creating or running an experiment, you need to (1) make the relevant changes, (2) commit the changes, and (3) tag the commit. Existing experiments are located within their own branches. For instance, to run an ```aflfast``` experiment, run the following:
```
git branch aflfast origin/aflfast   # fetch the aflfast branch
git tag <tag_name> <commit_hash>    # tag which commit you want to run the expt on
./raf-commit <tag_name>             # must be run in order to generate a raf-tag
```
**NOTE:** If you have uncommitted changes or do not have a tag associated with the commit you want to run the experiment on, the campaign will not run. 
To start the campaign
```
(venv) ./raf-run
```
This will create the the name of the campaign id using the commit hash and the tag name. This script will create/update the proto files, build all the docker images for this campaign, and then start up the campaign. 
## Monitoring RAF:

#### Monitoring Cluster with Script
Under `spitfire/utils` we have included a sample monitoring script, `monitor.py`, that will display statistics and graphs regarding the fuzzing events that have occurred throughout the fuzzing campaign in the cluster. To run, you first need to make sure the following python packages are installed: 
```
(venv) python3 -m pip install grpcio grpcio-tools hydra-core pyyaml oogle-api-python-client protobuf google-auth kubernetes
```
You also need to make sure you have a way of displaying these graphs if you are running the cluster inside a non-GUI host (X11 forwarding with ssh is a good option). You then can run the `monitor.py`. 
```
(venv) python3.6 monitor.py
```
#### Monitoring Cluster Manually
To debug or get status updates about the pods that are running, run any of the following:
```
kubectl get pods
kubectl describe pod <pod-name>
kubectl logs <pod-name>
```
This first of these displays the pod's `name` (used in commands after) and the pod's `status` (usually one of Pending, Initx:x, Running, Completed, Error). 
- Jobs run to completion so should display a Completed status when they are finished. 
- Deployments/Services run indefinitely so should display a Running status.

The second command displays detailed information about the pod's configuration and events and the last command displays the output (e.g. print statements) from the container running inside the pod.

Note: These commands can display information about any Kubernetes object. The general case is as follows: 
```
kubectl get <object>
kubectl describe <object> <object-name>
```
See documentation at https://kubernetes.io/docs/reference/kubectl/overview/ for more information on how to use kubectl. 
#### Monitoring a Campaign 
Note: The above commands show objects, by default, in the **default** namespace only. If there is nothing running in the default namespace, nothing will be displayed. In order to see the kubernetes objects in a different namespace (i.e. in a specific campaign), run the following:
```
kubectl config set-context --current --namespace=<campaign-id> 
```
#### Exec a Pod
In order to get a shell to a **running** container (useful for debugging and testing), run the following:
```
kubectl exec -it <pod-name> -- bash
```
## Suspending a campaign
To suspend, you can simply run the following script to patch and suspend the fuzzing manager cron job that drives the campaign.  
```
./suspend.sh <campaign-id>
```
## Cleaning up
In order to clean up all the kubernetes objects from the campaign, run the following:
```
./stop.sh <campaign-id> 
```



