#!/bin/bash
kubectl delete service grpc-server && kubectl delete deployment grpc-server
kubectl delete configmap dir-config
kubectl delete job init
kubectl delete cronjob fm

kjobs=`kubectl get jobs | grep -v NAME | awk '{print $1}'`
for j in $kjobs
do
    echo $j
    kubectl delete job $j
done
kubectl delete pvc default
