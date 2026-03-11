#!/usr/bin/env bash

set -ex

RUNS=$1
PARALLEL=$2
TIMEOUT_FACTOR=$3

test_scripts=$(python3 -c "import sys; import os; sys.path.append(os.path.abspath('build/test/functional')); from test_runner import ALL_SCRIPTS; print(' '.join(s for s in ALL_SCRIPTS if s.startswith('interface_ipc')))")
test_args=()
for _ in $(seq 1 "${RUNS}"); do
  for script in $test_scripts; do
    test_args+=("$script")
  done
done
build/test/functional/test_runner.py "${test_args[@]}" --jobs "${PARALLEL}" --timeout-factor="${TIMEOUT_FACTOR}" --failfast --combinedlogslen=99999999
