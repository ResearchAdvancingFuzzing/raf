# RAF Setup

## Installation: 
Follow the instructions at https://kubernetes.io/docs/tasks/tools/install-minikube/ to install minikube, kubectl, and optionally (see below) a hypervisor (e.g. virtualbox). The instructions for linux are reproduced below for convenience: 
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
On your host computer, you need to have python3.6 installed as well as the following python packages in order to make the grpcio python files from the .proto file in the run script.
```
sudo apt-get install python3-pip
sudo python3.6 -m pip install grpcio
sudo python3.6 -m pip install grpcio-tools
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
sudo groupadd docker # Note this group may already be added
sudo usermod -aG docker $USER 
sudo minikube start --vm-driver=none
sudo chown -R $USER $HOME/.minikube
```
**NOTE**: You need to log out and log back in for the docker permissions to take effect.
## Setup RAF:
After cloning this repository, run the `run` script in order to pull the gtfo repo, create the docker images, and make the grpc proto files. 
```
cd raf
./run
```
## Running RAF:
After all the docker images are built, we are ready to deploy objects into the cluster. Start with the following to add the objects that will _initialize the cluster environment_, _start up the knowledge base grpc server_, and _start up the fuzzing manager_.
```
./start.sh
```
This will create the initial Kubernetes yaml objects, defined in the `config_init.yaml` file (including the init job which will then start up the server and the fuzzing manager.)  You should see the following output if done correctly. 
```
role.rbac.authorization.k8s.io/job-create created
rolebinding.rbac.authorization.k8s.io/create-jobs created
configmap/dir-config created
persistentvolume/data-pv created
persistentvolumeclaim/seed-corpus-pv-claim created
persistentvolumeclaim/replay-pv-claim created
persistentvolumeclaim/spitfire-pv-claim created
persistentvolumeclaim/target-pv-claim created
persistentvolumeclaim/inputs-pv-claim created
persistentvolumeclaim/target-instr-pv-claim created
job.batch/init created
```
## Monitoring RAF:
After this init job has completed, the fuzzing manager cron job will be left to run the individual (fuzzing, taint, coverage) jobs. Their object specifications are found in their respective `spitfire/fuzzing-manager/jobs/config-{job_type}.yaml` file. 

#### Monitoring Kubernetes Pods
In order to debug / get status updates about the pods that are running, run any of the following:
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
## Cleaning up
In order to clean up all the kubernetes objects from the campaign, run the following:
```
./stop.sh
```



