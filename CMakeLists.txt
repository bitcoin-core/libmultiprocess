# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Top-level wrapper for standalone builds (`cmake -S .`). Adds the example
# subdirectory, which is the only thing not relevant to subtree consumers
# (which configure `lib/` directly via `add_subdirectory()`).
#
# The actual library, generator, headers, tests and pkg-config template live
# under `lib/` so that `git subtree split --prefix=lib` produces a `lib`
# branch suitable for use as a slim git subtree by downstream projects.

cmake_minimum_required(VERSION 3.12)

project("Libmultiprocess" CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

# Tell lib/CMakeLists.txt that this is a standalone build, even though it is
# being processed via add_subdirectory() rather than as the top-level source.
set(MP_STANDALONE TRUE)
include(CTest)

# Threads::Threads and Cap'n Proto targets are needed by the example/
# subdirectory. find_package() creates IMPORTED targets in the calling
# directory's scope, so do it here as well as in lib/CMakeLists.txt.
find_package(Threads REQUIRED)
find_package(CapnProto 0.7 QUIET NO_MODULE)

add_subdirectory(lib)
add_subdirectory(example EXCLUDE_FROM_ALL)
