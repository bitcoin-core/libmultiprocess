CI_DESC="CI config for OpenIndiana"
CI_DIR=build-openindiana
# OpenIndiana does not package Cap'n Proto, so build it from source.
CAPNP_CHECKOUT=v1.5.0
# KJ fibers do not work on illumos.
CAPNP_CMAKE_ARGS=(-DWITH_FIBERS=OFF)
# The -pthread flag works around a bug in CMake's FindThreads module.
# See https://gitlab.kitware.com/cmake/cmake/-/issues/26063.
export CXXFLAGS="-pthread -Werror -Wall -Wextra -Wpedantic -Wunused -Wunused-const-variable"
# The socket API lives in libsocket on illumos.
CMAKE_ARGS=(-G Ninja -DCMAKE_EXE_LINKER_FLAGS=-lsocket)
BUILD_ARGS=(-k 0)
