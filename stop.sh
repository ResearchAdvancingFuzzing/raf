#!/bin/bash
kubectl delete -f spitfire/init/init/config_fm.yaml
kubectl delete -f spitfire/init/init/config_server.yaml
kjobs=`kubectl get jobs | grep -v NAME | awk '{print $1}'`
for j in $kjobs
do
    echo $j
    kubectl delete job $j
done
kubectl delete -f config_init.yaml
