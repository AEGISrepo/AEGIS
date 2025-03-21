# date -u
# phoronix-test-suite batch-benchmark foricse26-0

# time sudo bash benchmark.sh 2>&1 | tee benchmark-$(date +%Y%m%d-%H%M%S).log

# check not root exit
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

wait_process_d_state() {
    local process_name='bpftrace' #
    local max_wait=120
    local wait_count=0

    while [ $wait_count -lt "$max_wait" ]; do
        #  D
        if ! ps -C "$process_name" -o stat= 2>/dev/null | grep -q 'D'; then
            return
        fi

        echo "$process_name  D ... [$wait_count]"
        sleep 1
        wait_count=$((wait_count + 1))
    done

    echo "[$(date +'%H:%M:%S')] ：$process_name ，！..." >&2
}

echo "Baseline:"
su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"

echo "Run bpftrace:"
pkill bpftrace
sleep 2
echo " run_n.sh 1"
bash run_n.sh 1

wait_process_d_state
sleep 2

su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"
pkill bpftrace
# done

sleep 2

echo "Baseline:"
su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"

#  4
# run_n.sh 4

pkill bpftrace
sleep 2
echo " run_n.sh 4"
bash run_n.sh 4

wait_process_d_state
sleep 2

su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"
pkill bpftrace

sleep 2

#  8
# run_n.sh 8

pkill bpftrace
sleep 2
echo " run_n.sh 8"
bash run_n.sh 8

wait_process_d_state
sleep 2

su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"
pkill bpftrace

sleep 2

echo "Baseline:"
su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"

#  16
# run_n.sh 16

echo "Run bpftrace:"
echo " 1 :"

pkill bpftrace
sleep 2
echo " run_n.sh 16"
bash run_n.sh 16

wait_process_d_state
sleep 2

su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"
pkill bpftrace

sleep 2

echo "Baseline:"
su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"

#  32
# run_n.sh 32

echo "Run bpftrace:"
echo " 1 :"

pkill bpftrace
sleep 2
echo " run_n.sh 32"
bash run_n.sh 32

wait_process_d_state
sleep 2

su - anony -c "echo 'Switched to user'; whoami; which phoronix-test-suite;date -u;time phoronix-test-suite batch-benchmark foricse26-0"
echo "--------------------------------"
pkill bpftrace
