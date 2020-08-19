# RAF Setup

## Installation: 
Follow the instructions at https://kubernetes.io/docs/tasks/tools/install-minikube/ to install minikube, kubectl, and optionally (see below) a hypervisor (e.g. virtualbox). The instructions to install minikube and kubectl for linux are reproduced below for convenience: 
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
#### gRPC setup
On your host computer, you need to have python3.6 and pip already installed. 
```
sudo apt-get install python3.6 python3-pip
```
You then need to install the the following python packages in order to make the grpcio python files from the .proto file in the run script.
```
sudo python3.6 -m pip install grpcio  grpcio-tools
```
#### Minikube setup
Run **one** of the following sets of commands to setup the single-node Kubernetes cluster: 
1. In a virtual machine on your host computer: 
Run the following commands in order to set up the cluster in a virtual machine on your personal computer and configure your environment to re-use the docker daemon inside the minikube instance. NOTE: you need to make sure that the virtualbox has enough memory (greater than the default)! 
```
minikube start --vm-driver=virtualbox
eval $(minikube docker-env)
```
2. On your host computer: 
If you have a linux environment you can use the following to set the cluster up on your **host**.
```
sudo apt-get update
sudo apt-get install conntrack docker.io
sudo groupadd docker # Note this group may already be added; that is ok
sudo usermod -aG docker $USER 
sudo minikube start --vm-driver=none
sudo chown -R $USER $HOME/.minikube
sudo chown -R $USER $HOME/.kube
```
**NOTE**: You need to log out and log back in for the docker permissions to take effect.
## Setup RAF directory:
After cloning this repository, run the `setup.sh` script in order to pull the gtfo repo and make a sample seed corpus. 
```
git clone <this_repo> 
cd raf
./setup.sh 
```
Note: Run this only once, when you have a clean clone of the RAF repo. 
## Build a campaign 
After initial setup, run the `build.sh` script. This takes in one parameter: the name of the campaign id (this id must be unique among all campaigns). This script will create the proto files, build all the docker images for this campaign, and then start up the campaign.
```
./build.sh <campaign-id>
```
## Monitoring RAF:

#### Monitoring Cluster with Script
Under `spitfire/utils` we have included a sample monitoring script, `monitor.py`, that will display statistics and graphs regarding the fuzzing events that have occurred throughout the fuzzing campaign in the cluster. To run, you first need to make sure the following python packages are installed: 
```
pip3 install grpcio grpcio-tools hydra-core
pip3 install pyyaml 
pip3 install google-api-python-client protobuf 
pip3 install google-auth

git clone --recursive https://github.com/kubernetes-client/python.git
cd python
sudo python3.6 setup.py install 
```
You also need to make sure you have a way of displaying these graphs if you are running the cluster inside a non-GUI host (X11 forwarding with ssh is a good option). You then can run the `monitor.py`. 
```
python3.6 monitor.py
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



