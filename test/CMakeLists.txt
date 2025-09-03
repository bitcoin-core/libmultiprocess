# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

if(BUILD_TESTING AND TARGET CapnProto::kj-test)
  set_property(SOURCE ${MP_PROXY_HDRS} PROPERTY GENERATED 1)

  add_executable(mptest
    ${MP_PROXY_HDRS}
    mp/test/foo-types.h
    mp/test/foo.h
    mp/test/test.cpp
  )
  include(${PROJECT_SOURCE_DIR}/cmake/TargetCapnpSources.cmake)
  target_capnp_sources(mptest ${CMAKE_CURRENT_SOURCE_DIR} mp/test/foo.capnp)
  target_include_directories(mptest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(mptest PRIVATE CapnProto::kj-test)
  target_link_libraries(mptest PRIVATE Threads::Threads)

  add_test(NAME mptest COMMAND mptest)
endif()
