cmake_minimum_required(VERSION 3.24)
project(RTHModdingTool VERSION 0.1.0 LANGUAGES CXX)

option(RTH_BUILD_TESTS "Build the unit tests" ON)
option(RTH_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

add_library(rth_core src/core/binary_reader.cpp src/core/analyzer.cpp)
target_include_directories(rth_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(rth_core PUBLIC cxx_std_20)

if(MSVC)
  target_compile_options(rth_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(rth_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()
if(RTH_ENABLE_SANITIZERS AND NOT MSVC)
  target_compile_options(rth_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rth_core PUBLIC -fsanitize=address,undefined)
endif()

add_executable(rthtool src/cli/main.cpp)
target_link_libraries(rthtool PRIVATE rth_core)

if(RTH_BUILD_TESTS)
  include(CTest)
  add_executable(rth_core_tests tests/test_core.cpp)
  target_link_libraries(rth_core_tests PRIVATE rth_core)
  add_test(NAME rth_core_tests COMMAND rth_core_tests)

  add_test(
    NAME rthtool_cli_integration
    COMMAND ${CMAKE_COMMAND}
      "-DRTH_TOOL=$<TARGET_FILE:rthtool>"
      "-DTEST_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-test-work"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_integration.cmake"
  )

  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(
      NAME rth_research_tool_tests
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_research_tools.py"
    )
    add_test(
      NAME rth_sblk_v3_tests
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_sblk_v3.py"
    )
    add_test(
      NAME rth_ffmpeg_psxadpcm_tests
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ffmpeg_psxadpcm.py"
    )
  endif()
endif()
