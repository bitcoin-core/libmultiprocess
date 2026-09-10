CI_DESC="CI config for OpenBSD"
CI_DIR=build-openbsd
export CXXFLAGS="-Werror -Wall -Wextra -Wpedantic -Wunused -Wno-c++23-lambda-attributes"
CMAKE_ARGS=(-G Ninja)
BUILD_ARGS=(-k 0)
