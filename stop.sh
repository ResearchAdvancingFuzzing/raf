#!/bin/bash

namespace=$1

if [ -z "$namespace" ]
then 
    echo "Usage: ./stop.sh <campaign-id>"
    exit 1
fi

kubectl delete cronjob fm -n $namespace
kubectl delete job init -n $namespace
kubectl delete service grpc-server -n $namespace
kubectl delete deployment grpc-server -n $namespace
kubectl delete configmap dir-config -n $namespace

kjobs=`kubectl get jobs | grep -v NAME | awk '{print $1}'`
for j in $kjobs
do
    echo $j
    kubectl delete job $j -n $namespace
done

kubectl delete pvc $namespace
kubectl delete pv "$namespace-pv"
kubectl delete namespace $namespace

