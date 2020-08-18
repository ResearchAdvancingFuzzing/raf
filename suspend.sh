#!/bin/bash

namespace=$1
if [ -z "$namespace" ]
then 
    echo "Usage: ./suspend.sh <campaign-id>"
    exit 1
fi

kubectl patch cronjob fm --namespace="$namespace" -p '{"spec" : {"suspend" : true }}'
