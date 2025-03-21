#!/bin/bash


if [ $# -ne 1 ]; then
    echo "Usage: $0 <number (1-32)>"
    exit 1
fi

num="$1"


mapfile -t cve_dirs < <(
    find . -maxdepth 1 -type d -name 'CVE-*' | while read -r dir; do
        if find "$dir" -maxdepth 1 -type f \( -name '*.bt' -o -name '*.bt' \) | grep -q .; then
            echo "$dir"
        fi
    done | sort -u
)

total=${#cve_dirs[@]}
if [ "$total" -eq 0 ]; then
    exit 1
fi


if [ "$num" -gt "$total" ]; then
    num=$total
fi

# rm -f "./bpftrace_output.log"

OUTPUT_FILE="../bpftrace_output.log"


selected_dirs=($(shuf -e "${cve_dirs[@]}" | head -n "$num"))

echo "Starting $num monitors..."
for dir in "${selected_dirs[@]}"; do
    (
        cd "$dir" || exit
        for file in *.bt; do
            if [ -f "$file" ]; then
                echo "$file (in $dir)"
                nohup bpftrace "$file" >> "$OUTPUT_FILE" 2>&1 &
            fi
        done
    ) &
done

wait
