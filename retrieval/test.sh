#!/bin/env bash
set -x #echo on

time python -u findfunc.py ../../ vfs_open
time python -u findstruct.py ../../ task_struct
time python -u finddefine.py ../../ TASK_COMM_LEN
time python -u finddefine.py ../../ BFQQE_BUDGET_EXHAUSTED