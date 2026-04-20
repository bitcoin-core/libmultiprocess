CI_DESC="CI job cross-compiling to Windows (MinGW UCRT) and testing with Wine"
CI_DIR=build-windows
# Cache the cross-toolchain closure to avoid rebuilding mingw + wine every run.
CI_CACHE_NIX_STORE=true

# Wine needs a writable prefix and XDG_RUNTIME_DIR to talk to its services.
# Pre-create the prefix outside of the nix shell so we can plumb it through
# (the shell uses --ignore-environment).
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-libmultiprocess}"
export WINEARCH="${WINEARCH:-win64}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$WINEPREFIX"
# Silence wine's verbose warnings about missing Windows features during tests.
export WINEDEBUG=-all

NIX_ARGS=(
  --arg minimal true
  --arg enableWine true
  # Pin capnproto v1.4.0: v1.3.0 includes the upstream fix that moves
  # cidr.c++ into kj-async (capnproto@a2deb05) so we no longer need a local
  # patch for that, and v1.4.0 is the current stable release.
  --arg capnprotoVersion '"1.4.0"'
  --arg crossPkgs 'import <nixpkgs> { crossSystem = { config = "x86_64-w64-mingw32"; libc = "ucrt"; }; }'
  # Wine stores its prefix under $HOME; preserve HOME so wineboot can initialize.
  --keep HOME
  --keep WINEPREFIX
  --keep WINEARCH
  --keep WINEDEBUG
  --keep XDG_RUNTIME_DIR
)
export CXXFLAGS="-Werror -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wa,-mbig-obj"

# When sourced from inside the nix shell (during ci.sh), initialize wine and
# pick up native capnp tools to use for build-time code generation. These
# steps are no-ops when sourced from outside the shell (e.g. by run.sh).
if command -v wineboot >/dev/null 2>&1; then
  wineboot --init >/dev/null 2>&1 || true
fi
CAPNP_NATIVE=$(command -v capnp 2>/dev/null || true)
CAPNPC_CXX_NATIVE=$(command -v capnpc-c++ 2>/dev/null || true)

CMAKE_ARGS=(
  -G Ninja
  # Tell CMake we're targeting Windows so FindThreads picks Win32 threads
  # and other platform checks behave correctly.
  -DCMAKE_SYSTEM_NAME=Windows
  -DCMAKE_SYSTEM_PROCESSOR=x86_64
  # Run target-arch executables (mpgen, capnpc, mptest) through wine64.
  -DCMAKE_CROSSCOMPILING_EMULATOR=wine64
  # Avoid pulling in libgcc_s_seh-1.dll and libstdc++-6.dll at runtime.
  -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++"
  # Use native capnp/capnpc-c++ for build-time code generation so cmake
  # doesn't try to exec target-arch .exe binaries directly.
  ${CAPNP_NATIVE:+-DCAPNP_EXECUTABLE=$CAPNP_NATIVE}
  ${CAPNPC_CXX_NATIVE:+-DCAPNPC_CXX_EXECUTABLE=$CAPNPC_CXX_NATIVE}
)
BUILD_ARGS=(-k 0)
