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

# clone a seed corpus
git clone https://github.com/ResearchAdvancingFuzzing/panda-replays.git spitfire/init/panda-replays
mv spitfire/init/panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit/inputs spitfire/init/corpus


