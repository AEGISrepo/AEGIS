#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

USER="anonymous"
TEST_SUITE="ndss26bench"

print_separator() {
    echo "--------------------------------"
}

run_baseline() {
    echo "Baseline:"
    su - "$USER" -c "
        echo 'Switched to user';
        whoami;
        which phoronix-test-suite;
        date -u;
        time phoronix-test-suite batch-benchmark $TEST_SUITE
    "
    print_separator
}

wait_process_d_state() {
    local process_name='bpftrace'
    local max_wait=120
    local wait_count=0

    while [ $wait_count -lt "$max_wait" ]; do
        if ! ps -C "$process_name" -o stat= 2>/dev/null | grep -q 'D'; then
            return 0
        fi
        echo "$process_name is in D state... [$wait_count]"
        sleep 1
        wait_count=$((wait_count + 1))
    done

    echo "[$(date +'%H:%M:%S')] Warning: $process_name did not stabilize, timeout! Continuing..." >&2
}

run_bpftrace_with_sample() {
    local sample=$1
    pkill bpftrace 2>/dev/null || true
    sleep 2

    echo "Run bpftrace:"
    echo "Running run_n.sh $sample"
    bash run_n.sh "$sample"

    wait_process_d_state
    sleep 2

    su - "$USER" -c "
        echo 'Switched to user';
        whoami;
        which phoronix-test-suite;
        date -u;
        time phoronix-test-suite batch-benchmark $TEST_SUITE
    "
    print_separator
    pkill bpftrace 2>/dev/null || true
    sleep 2
}

main() {
    local tests=(
        "baseline"
        "1"
        "4"
        "8"
        "16"
        "32"
        "64"
        "baseline"
    )

    for item in "${tests[@]}"; do
        if [ "$item" = "baseline" ]; then
            run_baseline
        else
            run_bpftrace_with_sample "$item"
        fi
    done

    echo "All benchmarks completed."
}

main "$@"