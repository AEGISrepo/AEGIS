#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <number (>=1)>"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

pkill bpftrace 2>/dev/null || true

num="$1"

mapfile -t all_bt_files < <(
    find ./bpfs -type f \( -name 'CVE-*.bt' -o \) | sort
)

total=${#all_bt_files[@]}
if [[ $total -eq 0 ]]; then
    echo "No matching .bt files found."
    exit 1
fi


SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CASCADE_FILE="$SCRIPT_DIR/.cascade.lst"

if [[ ! -f "$CASCADE_FILE" ]]; then
    printf '%s\n' "${all_bt_files[@]}" | shuf > "$CASCADE_FILE"
fi

mapfile -t selected_files < <(head -n "$num" "$CASCADE_FILE")

OUTPUT_FILE="$(pwd)/bpftrace_output.log"

echo "Starting ${#selected_files[@]} bpftrace monitors..."

MAX_LINES_PER_SCRIPT=100

for bt_file in "${selected_files[@]}"; do
    (
        dir=$(dirname "$bt_file")
        fname=$(basename "$bt_file")
        cd "$dir" || exit 1
        echo "Running: bpftrace $fname (in $dir)"
        nohup bpftrace "$fname" 2>&1 | head -n "$MAX_LINES_PER_SCRIPT" >> "$OUTPUT_FILE" &
    )
done

wait

running_count=$(pgrep bpftrace | wc -l)
echo "Currently $running_count bpftrace processes are running."