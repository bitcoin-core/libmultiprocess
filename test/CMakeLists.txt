# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Custom test targets for convenience, based on
# https://gitlab.kitware.com/cmake/community/-/wikis/doc/tutorials/EmulateMakeCheck.
#
# CTest already provides a "make test" target, but it just runs existing tests
# that were previously built, without building anything itself. Define "make
# tests" here as a custom target to build all available tests and "make check"
# as a custom target to build and run them.
add_custom_target(mptests)
add_custom_target(mpcheck COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS mptests)

# Only add more convenient tests and check targets if project is being built
# standalone, to prevent clashes with external projects.
if (MP_STANDALONE)
  add_custom_target(tests DEPENDS mptests)
  add_custom_target(check DEPENDS mpcheck)
endif()

if(BUILD_TESTING AND TARGET CapnProto::kj-test)
  set_property(SOURCE ${MP_PROXY_HDRS} PROPERTY GENERATED 1)

  add_executable(mptest
    ${MP_PROXY_HDRS}
    mp/test/foo-types.h
    mp/test/foo.h
    mp/test/listen_tests.cpp
    mp/test/spawn_tests.cpp
    mp/test/connect_tests.cpp
    mp/test/test.cpp
  )
  include(${PROJECT_SOURCE_DIR}/cmake/TargetCapnpSources.cmake)
  target_capnp_sources(mptest ${CMAKE_CURRENT_SOURCE_DIR} mp/test/foo.capnp)
  target_include_directories(mptest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(mptest PRIVATE CapnProto::kj-test)
  target_link_libraries(mptest PRIVATE Threads::Threads)

  add_dependencies(mptests mptest)
  add_test(NAME mptest COMMAND mptest)

  # This test overrides clock_gettime() to force CLOCK_MONOTONIC backwards.
  # Use a separate executable so other tests keep using the system clock.
  # Linux Cap'n Proto versions before 1.2 throw on these backward readings.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(mpclocktest mp/test/clock_tests.cpp)
    target_link_libraries(mpclocktest PRIVATE
      Libmultiprocess::multiprocess CapnProto::kj-test Threads::Threads ${CMAKE_DL_LIBS}
    )
    add_dependencies(mptests mpclocktest)
    add_test(NAME mpclocktest COMMAND mpclocktest)
    set_tests_properties(mpclocktest PROPERTIES TIMEOUT 30)
  endif()
endif()
