# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

cmake_minimum_required(VERSION 3.12..4.1)

project(LibmultiprocessSupport CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

set(MP_SOURCE_DIR ".." CACHE PATH "Path to the libmultiprocess source directory.")
get_filename_component(MP_SOURCE_DIR "${MP_SOURCE_DIR}" ABSOLUTE)
include(CTest)
add_subdirectory("${MP_SOURCE_DIR}" libmultiprocess)

find_package(Threads REQUIRED)
add_subdirectory(example)
