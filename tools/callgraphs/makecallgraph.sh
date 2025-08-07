#!/bin/env bash
set -x #echo on


callgraphpyPath="callgraph.py"

if [[ -n "$1" ]]; then
    callgraphpyPath="$1"
fi

if [ ! -f "$callgraphpyPath" ]; then
    echo "$callgraphpyPath not found"
    echo "Usage:  <path to callgraph.py>"
    exit 1
fi

current_path=$(pwd)
last_component=$(basename "$current_path")

echo "$last_component"

make "KCFLAGS=-fdump-rtl-expand" -j$(nproc)

# check return value
if [ $? -ne 0 ]; then
    echo "Error: make failed"
    exit 1
fi

egypt **/*.expand >"callgraph_$last_component.dot"

if [ $? -ne 0 ]; then
    echo "Error: egypt failed"
    exit 1
fi

# conda activate langchain

echo "You should run this script in a conda environment with required dependencies installed"

python3 "$callgraphpyPath" "callgraph_$last_component.dot" "callgraph_$last_component.sqlite"

if [ $? -ne 0 ]; then
    echo "python3 "$callgraphpyPath": failed"
    exit 1
fi

du -sh "callgraph_$last_component."*