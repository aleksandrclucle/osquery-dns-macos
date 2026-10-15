# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.21)
# Consumed by osquery's external/extension_dns_events directory.
if(NOT COMMAND addOsqueryExtension)
  message(FATAL_ERROR "Build the extension with scripts/build.sh; for offline tests use cmake -S tests -B build/tests")
endif()
if(NOT APPLE)
  message(FATAL_ERROR "The DNS event source requires macOS")
endif()
enable_language(OBJCXX)
addOsqueryExtension(dns_events
  src/main.cpp
  src/events.cpp
  src/parser.cpp
  src/native_stream.mm
)
set_source_files_properties(src/native_stream.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc -fblocks")
target_include_directories(dns_events PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
