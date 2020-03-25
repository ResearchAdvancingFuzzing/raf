# RAF Setup

## Installation: 
Follow the instructions at https://kubernetes.io/docs/tasks/tools/install-minikube/ to install minikube, kubectl, and optionally (see below) a hypervisor (e.g. virtualbox). 
  
## Setup Env: 
Run the following commands in order to set up the single-node Kubernetes cluster in a virtual machine on your personal computer and configure your environment to re-use the docker daemon inside the minikube instance.
```
minikube start --vm-driver=virtualbox
eval $(minikube docker-env)
```
If you have docker **and** a linux environment you can use the following to set the cluster up on your **host**.
```
minikube start --vm-driver=none
```
## Setup RAF:
After cloning this repository, run the `run` script in order to pull the gtfo repo, create the docker images, and make the grpc proto files. 
```
cd raf
./run
```
## Running RAF:
After all the docker images are built, we are ready to deploy objects into the cluster. Start with the following to add the objects that will _initialize the cluster environment_ and _start up the knowledge base grpc server_.
```
kubectl apply -f config_init.yaml
```
This will create every Kubernetes yaml object defined in the `config_init.yaml` file. You should see the following output if done correctly. 
```
clusterrole.rbac.authorization.k8s.io/job-create created
clusterrolebinding.rbac.authorization.k8s.io/create-jobs created
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
After this init pod has completed (see Monitoring Kubernetes Objects below), you can create any of the jobs (fuzzer job, taint job, coverage job) listed in these config files. 
```
kubectl apply -f config_taint.yaml
kubectl apply -f config_fuzzer.yaml
kubectl apply -f config_coverage.yaml
```
Note: `config-{x}.yaml` contains the objects to run the {x} part of the system. For instance, `config-server.yaml` contains the Kubernetes objects to run the Knowledge Base grpc server. 
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

The second command displays detailed information about the pod's configuration and events and the last command displays the output (e.g. print statements) of the container running inside the pod (very useful for debugging).

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
#### Notes
- Right now a lot of the jobs are running an `./infinite` script so they stay up indefinitely and I can get a shell to the container and debug it. This can be easily changed in the respective Dockerfile for the image so that it runs the .py script it is supposed to run. 
- Also, as of now, the jobs in the `config_{x}.yaml` files that would be created by the fuzzing manager (taint, fuzzer, coverage) are created manually. After the init and fuzzing manager jobs are completed, all of these objects will be created by the fuzzing manager job and the only thing that will need to be run is the following: 
```
kubectl apply -f config_init.yaml
```




