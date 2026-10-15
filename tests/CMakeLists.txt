# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.21)
project(dns_events_tests LANGUAGES CXX)

enable_testing()
add_executable(dns_parser_tests parser_test.cpp ../src/parser.cpp)
target_compile_features(dns_parser_tests PRIVATE cxx_std_17)
target_compile_options(dns_parser_tests PRIVATE -UNDEBUG)
target_include_directories(dns_parser_tests PRIVATE ../src)
add_test(NAME parser COMMAND dns_parser_tests)

find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
add_test(NAME integration_helpers
  COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/test_integration_helpers.py")

# Explicit opt-in: this test subscribes to macOS logs and resolves example.com.
option(DNS_ENABLE_LIVE_TESTS "Build and register the live macOS stream test" OFF)
if(DNS_ENABLE_LIVE_TESTS)
  if(NOT APPLE)
    message(FATAL_ERROR "DNS_ENABLE_LIVE_TESTS requires macOS")
  endif()
  enable_language(OBJCXX)
  add_executable(dns_native_stream_tests native_stream_test.cpp ../src/native_stream.mm)
  target_compile_features(dns_native_stream_tests PRIVATE cxx_std_17)
  set_target_properties(dns_native_stream_tests PROPERTIES OBJCXX_STANDARD 17 OBJCXX_STANDARD_REQUIRED ON)
  set_source_files_properties(../src/native_stream.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc -fblocks")
  target_compile_options(dns_native_stream_tests PRIVATE -UNDEBUG)
  target_include_directories(dns_native_stream_tests PRIVATE ../src)
  target_link_libraries(dns_native_stream_tests PRIVATE "-framework Foundation")
  add_test(NAME native_stream_live COMMAND dns_native_stream_tests)
  set_tests_properties(native_stream_live PROPERTIES LABELS live TIMEOUT 60)
endif()
