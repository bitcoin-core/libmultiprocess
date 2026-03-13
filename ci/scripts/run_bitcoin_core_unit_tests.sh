#!/usr/bin/env bash

set -ex

RUNS=$1

for _ in $(seq 1 "${RUNS}"); do
  build/bin/test_bitcoin --run_test=ipc_tests,miner_tests --catch_system_error=no --log_level=nothing --report_level=no
done
