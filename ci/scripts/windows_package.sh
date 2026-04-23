#!/usr/bin/env bash
#
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Package cross-compiled Windows binaries + runtime DLLs into a directory
# suitable for uploading as a workflow artifact. Must be run inside the
# nix shell produced by `ci/configs/windows.bash` so the mingw toolchain
# (objdump, g++) is on PATH.

export LC_ALL=C.UTF-8

set -o errexit -o nounset -o pipefail -o xtrace

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

[ "${CI_CONFIG+x}" ] && source "$CI_CONFIG"
: "${CI_DIR:=build-windows}"

readonly BUILD_DIR="${REPO_DIR}/${CI_DIR}"
readonly ARTIFACT_DIR="${REPO_DIR}/windows-cross-artifact"

# Nix's cross stdenv exports these; fall back to the canonical names if not.
: "${CXX:=x86_64-w64-mingw32-g++}"
: "${OBJDUMP:=x86_64-w64-mingw32-objdump}"

copy_artifact_file() {
  install -D -m 0755 "$1" "${ARTIFACT_DIR}/$2"
}

# Runtime DLLs for cross-compiled dependencies live in the sibling bin/
# directory of each -L path the cross stdenv adds to NIX_LDFLAGS (e.g.
# capnproto, mcfgthreads). Collect those bin/ dirs once for dll lookup.
EXTRA_DLL_DIRS=()
for flag in ${NIX_LDFLAGS:-}; do
  case "${flag}" in
    -L*)
      candidate="${flag#-L}/../bin"
      [[ -d "${candidate}" ]] && EXTRA_DLL_DIRS+=("${candidate}")
      ;;
  esac
done

copy_runtime_dlls() {
  local exe="$1"
  local dll dll_path dir
  while read -r dll; do
    [[ -n "${dll}" ]] || continue
    # Skip DLLs that ship with Windows / Wine.
    case "${dll}" in
      ADVAPI32.dll|COMBASE.dll|COMCTL32.dll|GDI32.dll|KERNEL32.dll|OLE32.dll|OLEAUT32.dll|RPCRT4.dll|SHELL32.dll|UCRTBASE.dll|USER32.dll|WS2_32.dll)
        continue
        ;;
    esac
    dll_path="$(${CXX} -print-file-name="${dll}")"
    if [[ "${dll_path}" == "${dll}" || ! -f "${dll_path}" ]]; then
      dll_path=""
      for dir in "${EXTRA_DLL_DIRS[@]+"${EXTRA_DLL_DIRS[@]}"}"; do
        if [[ -f "${dir}/${dll}" ]]; then
          dll_path="${dir}/${dll}"
          break
        fi
      done
    fi
    if [[ -z "${dll_path}" || ! -f "${dll_path}" ]]; then
      case "${dll}" in
        lib*.dll)
          echo "Could not locate runtime DLL ${dll}." >&2
          exit 1
          ;;
        *)
          continue
          ;;
      esac
    fi
    install -D -m 0755 "${dll_path}" "${ARTIFACT_DIR}/${dll}"
  done < <(${OBJDUMP} -p "${exe}" | awk '/DLL Name: / {print $3}' | sort -u)
}

rm -rf "${ARTIFACT_DIR}"

readonly EXES=(
  test/mptest.exe
  example/mpexample.exe
  example/mpcalculator.exe
  example/mpprinter.exe
)

for exe in "${EXES[@]}"; do
  copy_artifact_file "${BUILD_DIR}/${exe}" "${exe}"
done

for exe in "${EXES[@]}"; do
  copy_runtime_dlls "${BUILD_DIR}/${exe}"
done
