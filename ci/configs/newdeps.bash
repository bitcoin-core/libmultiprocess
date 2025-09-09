CI_DESC="CI job using newest Cap'n Proto and cmake versions"
CI_DIR=build-newdeps
export CXXFLAGS="-Werror -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-error=array-bounds"
CAPNP_CHECKOUT=master
# cmakeVersion here should match policy version in CMakeLists.txt
NIX_ARGS=(--argstr capnprotoVersion "none" --argstr cmakeVersion "4.1.1")
BUILD_ARGS=(-k)
