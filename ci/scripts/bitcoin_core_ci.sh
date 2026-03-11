#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail -o xtrace

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/ci_helpers.sh"

replace_subtree() {
  rm -rf src/ipc/libmultiprocess
  cp -a _libmultiprocess src/ipc/libmultiprocess
  rm -rf src/ipc/libmultiprocess/.git
}

add_llvm_apt_repository() {
  curl -s "https://apt.llvm.org/llvm-snapshot.gpg.key" | sudo tee "/etc/apt/trusted.gpg.d/apt.llvm.org.asc" > /dev/null
  source /etc/os-release
  echo "deb http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-${LLVM_VERSION} main" | sudo tee "/etc/apt/sources.list.d/llvm.list"
  sudo apt-get update
}

install_llvm_alternatives() {
  sudo update-alternatives --install /usr/bin/clang++ clang++ "/usr/bin/clang++-${LLVM_VERSION}" 100
  sudo update-alternatives --install /usr/bin/clang clang "/usr/bin/clang-${LLVM_VERSION}" 100
  sudo update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer "/usr/bin/llvm-symbolizer-${LLVM_VERSION}" 100
}


configure_bitcoin_core() {
  local cmake_arg
  local cmake_args=()

  if [[ -n "${BITCOIN_CORE_CMAKE_ARGS:-}" ]]; then
    while IFS= read -r cmake_arg; do
      [[ -n "${cmake_arg}" ]] || continue
      cmake_args+=("${cmake_arg}")
    done <<< "${BITCOIN_CORE_CMAKE_ARGS}"
  fi

  cmake -S . -B build \
    --preset=dev-mode \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_GUI=OFF \
    -DBUILD_GUI_TESTS=OFF \
    -DWITH_ZMQ=OFF \
    -DWITH_USDT=OFF \
    -DBUILD_BENCH=OFF \
    -DBUILD_FUZZ_BINARY=OFF \
    -DWITH_QRENCODE=OFF \
    -G Ninja \
    "${cmake_args[@]}"
}

build_bitcoin_core() {
  cmake --build build --parallel "${BUILD_PARALLEL}"
}

run_ipc_unit_tests() {
  local runs="$1"

  for _ in $(seq 1 "${runs}"); do
    build/bin/test_bitcoin --run_test=ipc_tests,miner_tests --catch_system_error=no --log_level=nothing --report_level=no
  done
}

run_ipc_functional_tests() {
  local runs="$1"
  local timeout_factor="$2"
  local test_scripts
  local test_args=()

  test_scripts=$(python3 -c "import sys; import os; sys.path.append(os.path.abspath('build/test/functional')); from test_runner import ALL_SCRIPTS; print(' '.join(s for s in ALL_SCRIPTS if s.startswith('interface_ipc')))")
  for _ in $(seq 1 "${runs}"); do
    for script in $test_scripts; do
      test_args+=("$script")
    done
  done
  build/test/functional/test_runner.py "${test_args[@]}" --jobs "${PARALLEL}" --timeout-factor="${timeout_factor}" --failfast --combinedlogslen=99999999
}

main() {
  local command="${1:?missing command}"
  shift

  [[ "${command}" =~ ^[a-z_][a-z0-9_]*$ ]] || {
    echo "Invalid command: ${command}" >&2
    exit 1
  }

  if declare -F "${command}" >/dev/null; then
    "${command}" "$@"
  else
    echo "Unknown command: ${command}" >&2
    exit 1
  fi
}

main "$@"
