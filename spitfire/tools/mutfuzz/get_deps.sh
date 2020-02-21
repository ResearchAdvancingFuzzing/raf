#!/bin/bash
curl https://raw.githubusercontent.com/gaasedelen/lighthouse/master/plugin/lighthouse/parsers/drcov.py > drcov.py
patch drcov.py < spitfire/tools/mutfuzz/drcov.py.patch
mv drcov.py spitfire/tools/mutfuzz
