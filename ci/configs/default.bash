CI_DESC="CI job using default libraries and tools, and running IWYU"
CI_DIR=build-default
export CXXFLAGS="-Werror -Wall -Wextra -Wpedantic -Wextra-semi -Wunused -Wno-unused-command-line-argument -Wmissing-noreturn -Wtrailing-whitespace"
CMAKE_ARGS=(-DMP_ENABLE_IWYU=ON)
BUILD_ARGS=(-k)
