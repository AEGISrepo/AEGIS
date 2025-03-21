#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
fi

if [ $# -ne 1 ]; then
    echo "Usage: $0 <loop_count>"
    exit 1
fi

LOOP_COUNT=$1

if ! [[ "$LOOP_COUNT" =~ ^[0-9]+$ ]] || [ "$LOOP_COUNT" -le 0 ]; then
    echo "Error: Loop count must be a positive integer."
    exit 1
fi

for ((i = 1; i <= LOOP_COUNT; i++)); do
    echo "Running iteration $i of $LOOP_COUNT..."
    # echo "benchmark-$(date +%Y%m%d-%H%M%S).log"
    time bash benchmark.sh 2>&1 | tee "benchmark-$(date +%Y%m%d-%H%M%S).log"
done

echo "All iterations completed."
