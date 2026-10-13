CI_DESC="CI job using old Cap'n Proto and cmake versions"
CI_DIR=build-olddeps
# Pin olddeps to an older Nixpkgs channel, to be able to test an older GCC.
CI_NIXPKGS_CHANNEL=nixos-25.05
export CXXFLAGS="-Werror -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-error=array-bounds"
CAPNP_CHECKOUT=v0.9.2  # Use a checkout to compile it with the selected GCC
NIX_ARGS=(--argstr capnprotoVersion "none" --argstr cmakeVersion "3.22.6" --argstr gccVersion "10")
BUILD_ARGS=(-k)
