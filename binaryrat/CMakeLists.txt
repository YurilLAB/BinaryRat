# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.24)
project(BinaryRat VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(Threads REQUIRED)

add_library(binaryrat_core
  native/src/admission.cpp
  native/src/cache.cpp
  native/src/executor.cpp
  native/src/host.cpp
  native/src/live_cache.cpp
  native/src/ownership.cpp
  native/src/scheduler.cpp
  native/src/types.cpp)
target_compile_features(binaryrat_core PUBLIC cxx_std_20)
target_include_directories(binaryrat_core PUBLIC native/include)
target_include_directories(binaryrat_core SYSTEM PUBLIC native/third_party)
target_link_libraries(binaryrat_core PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(binaryrat_core PUBLIC psapi)
endif()
if(MSVC)
  target_compile_options(binaryrat_core PRIVATE /W4 /permissive- /EHsc)
else()
  target_compile_options(binaryrat_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(binaryrat-engine native/src/main.cpp)
target_link_libraries(binaryrat-engine PRIVATE binaryrat_core)
if(MINGW)
  target_link_options(binaryrat-engine PRIVATE -municode)
endif()
install(TARGETS binaryrat-engine RUNTIME DESTINATION bin)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/../NOTICE"
  DESTINATION share/licenses/BinaryRat)
install(FILES native/third_party/nlohmann/LICENSE.MIT
  DESTINATION share/licenses/BinaryRat/nlohmann)
install(FILES native/third_party/picosha2/LICENSE
  DESTINATION share/licenses/BinaryRat/picosha2)

if(BUILD_TESTING)
  foreach(test_name admission cache executor live_cache scheduler types ownership)
    add_executable(${test_name}_test native/tests/${test_name}_test.cpp)
    target_link_libraries(${test_name}_test PRIVATE binaryrat_core)
    add_test(NAME native.${test_name} COMMAND ${test_name}_test)
  endforeach()
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME native.protocol COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/native/tests/protocol_test.py" "$<TARGET_FILE:binaryrat-engine>")
endif()
