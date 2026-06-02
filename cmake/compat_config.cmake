# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# compat_config.cmake -- compatibility workarounds meant to be included after
# cmake find_package() calls are made, before configuring the ebuild

# Define capnp_PREFIX if not defined to avoid issue on macos
# https://github.com/bitcoin-core/libmultiprocess/issues/26

if (NOT DEFINED capnp_PREFIX AND DEFINED CAPNP_INCLUDE_DIRS)
  get_filename_component(capnp_PREFIX "${CAPNP_INCLUDE_DIRS}" DIRECTORY)
endif()

if (NOT DEFINED CAPNP_INCLUDE_DIRS AND DEFINED capnp_PREFIX)
  set(CAPNP_INCLUDE_DIRS "${capnp_PREFIX}/include")
endif()

if (NOT TARGET CapnProto::capnp_tool)
  if (DEFINED CAPNP_EXECUTABLE)
    add_executable(CapnProto::capnp_tool IMPORTED GLOBAL)
    set_target_properties(CapnProto::capnp_tool PROPERTIES IMPORTED_LOCATION "${CAPNP_EXECUTABLE}")
  elseif (DEFINED capnp_PREFIX)
    add_executable(CapnProto::capnp_tool IMPORTED GLOBAL)
    set_target_properties(CapnProto::capnp_tool PROPERTIES IMPORTED_LOCATION "${capnp_PREFIX}/bin/capnp")
  endif()
endif()

if (NOT TARGET CapnProto::capnpc_cpp)
  if (DEFINED CAPNPC_CXX_EXECUTABLE)
    add_executable(CapnProto::capnpc_cpp IMPORTED GLOBAL)
    set_target_properties(CapnProto::capnpc_cpp PROPERTIES IMPORTED_LOCATION "${CAPNPC_CXX_EXECUTABLE}")
  elseif (DEFINED capnp_PREFIX)
    add_executable(CapnProto::capnpc_cpp IMPORTED GLOBAL)
    set_target_properties(CapnProto::capnpc_cpp PROPERTIES IMPORTED_LOCATION "${capnp_PREFIX}/bin/capnpc-c++")
  endif()
endif()

# Validate CapnProto tool target locations and fix if broken.
# Some packaged capnproto versions (e.g., Ubuntu Noble libcapnp-dev 1.0.1)
# have incorrect IMPORTED_LOCATION paths due to a packaging bug where the cmake
# config file is installed under /usr/lib/.../cmake/ but the _IMPORT_PREFIX
# calculation goes up too few directory levels, yielding /usr/lib/bin/capnp
# instead of the correct /usr/bin/capnp.
foreach(_mp_tool IN ITEMS capnp_tool capnpc_cpp)
  if (TARGET "CapnProto::${_mp_tool}")
    get_target_property(_mp_configs "CapnProto::${_mp_tool}" IMPORTED_CONFIGURATIONS)
    set(_mp_valid FALSE)
    foreach(_mp_cfg IN LISTS _mp_configs)
      get_target_property(_mp_loc "CapnProto::${_mp_tool}" "IMPORTED_LOCATION_${_mp_cfg}")
      if (EXISTS "${_mp_loc}")
        set(_mp_valid TRUE)
        break()
      endif()
    endforeach()
    if (NOT _mp_valid)
      get_target_property(_mp_loc "CapnProto::${_mp_tool}" IMPORTED_LOCATION)
      if (EXISTS "${_mp_loc}")
        set(_mp_valid TRUE)
      endif()
    endif()
    if (NOT _mp_valid)
      if ("${_mp_tool}" STREQUAL "capnp_tool")
        find_program(_mp_fixed capnp HINTS "${capnp_PREFIX}/bin")
      else()
        find_program(_mp_fixed capnpc-c++ HINTS "${capnp_PREFIX}/bin")
      endif()
      if (_mp_fixed)
        foreach(_mp_cfg IN LISTS _mp_configs)
          set_target_properties("CapnProto::${_mp_tool}" PROPERTIES "IMPORTED_LOCATION_${_mp_cfg}" "${_mp_fixed}")
        endforeach()
        set_target_properties("CapnProto::${_mp_tool}" PROPERTIES IMPORTED_LOCATION "${_mp_fixed}")
      endif()
      unset(_mp_fixed CACHE)
    endif()
  endif()
endforeach()
unset(_mp_tool)
unset(_mp_configs)
unset(_mp_valid)
unset(_mp_cfg)
unset(_mp_loc)

if (NOT DEFINED CAPNPC_OUTPUT_DIR)
  set(CAPNPC_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

# CMake target definitions for backwards compatibility with Ubuntu bionic
# capnproto 0.6.1 package (https://packages.ubuntu.com/bionic/libcapnp-dev)
# https://github.com/bitcoin-core/libmultiprocess/issues/27

if (NOT DEFINED CAPNP_LIB_CAPNPC AND DEFINED CAPNP_LIB_CAPNP-RPC)
  string(REPLACE "-rpc" "c" CAPNP_LIB_CAPNPC "${CAPNP_LIB_CAPNP-RPC}")
endif()

if (NOT DEFINED CapnProto_capnpc_IMPORTED_LOCATION AND DEFINED CapnProto_capnp-rpc_IMPORTED_LOCATION)
  string(REPLACE "-rpc" "c" CapnProto_capnpc_IMPORTED_LOCATION "${CapnProto_capnp-rpc_IMPORTED_LOCATION}")
endif()

if (NOT TARGET CapnProto::capnp AND DEFINED CAPNP_LIB_CAPNP)
  add_library(CapnProto::capnp SHARED IMPORTED)
  set_target_properties(CapnProto::capnp PROPERTIES IMPORTED_LOCATION "${CAPNP_LIB_CAPNP}")
endif()

if (NOT TARGET CapnProto::capnpc AND DEFINED CAPNP_LIB_CAPNPC)
  add_library(CapnProto::capnpc SHARED IMPORTED)
  set_target_properties(CapnProto::capnpc PROPERTIES IMPORTED_LOCATION "${CAPNP_LIB_CAPNPC}")
endif()

if (NOT TARGET CapnProto::capnpc AND DEFINED CapnProto_capnpc_IMPORTED_LOCATION)
  add_library(CapnProto::capnpc SHARED IMPORTED)
  set_target_properties(CapnProto::capnpc PROPERTIES IMPORTED_LOCATION "${CapnProto_capnpc_IMPORTED_LOCATION}")
endif()

if (NOT TARGET CapnProto::capnp-rpc AND DEFINED CAPNP_LIB_CAPNP-RPC)
  add_library(CapnProto::capnp-rpc SHARED IMPORTED)
  set_target_properties(CapnProto::capnp-rpc PROPERTIES IMPORTED_LOCATION "${CAPNP_LIB_CAPNP-RPC}")
endif()

if (NOT TARGET CapnProto::kj AND DEFINED CAPNP_LIB_KJ)
  add_library(CapnProto::kj SHARED IMPORTED)
  set_target_properties(CapnProto::kj PROPERTIES IMPORTED_LOCATION "${CAPNP_LIB_KJ}")
endif()

if (NOT TARGET CapnProto::kj-async AND DEFINED CAPNP_LIB_KJ-ASYNC)
  add_library(CapnProto::kj-async SHARED IMPORTED)
  set_target_properties(CapnProto::kj-async PROPERTIES IMPORTED_LOCATION "${CAPNP_LIB_KJ-ASYNC}")
endif()
