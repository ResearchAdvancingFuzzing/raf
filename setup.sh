#!/bin/bash

# If you are starting with a clean git clone, run this once

# exit when any command fails
set -e 

# clone gtfo
gtfo_dir=spitfire/tools/gtfo-source/gtfo
if [[ -d "$gtfo_dir" ]]
then 
    echo "Error: $gtfo_dir already exists." 
    exit 1
else
    git clone https://github.com/ResearchAdvancingFuzzing/gtfo.git $gtfo_dir
fi



