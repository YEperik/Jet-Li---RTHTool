if(NOT DEFINED RTH_TOOL OR RTH_TOOL STREQUAL "")
  message(FATAL_ERROR "RTH_TOOL must be supplied")
endif()
if(NOT DEFINED TEST_WORK_DIR OR TEST_WORK_DIR STREQUAL "")
  message(FATAL_ERROR "TEST_WORK_DIR must be supplied")
endif()

file(REMOVE_RECURSE "${TEST_WORK_DIR}")
file(MAKE_DIRECTORY "${TEST_WORK_DIR}")
set(left_file "${TEST_WORK_DIR}/left.txt")
set(right_file "${TEST_WORK_DIR}/right.txt")
file(WRITE "${left_file}" "RTHsample\n")
file(WRITE "${right_file}" "RTHsample\nextra\n")

function(run_checked_test description expected_result)
  execute_process(
    COMMAND "${RTH_TOOL}" ${ARGN}
    RESULT_VARIABLE actual_result
    OUTPUT_VARIABLE actual_stdout
    ERROR_VARIABLE actual_stderr
  )
  if(NOT "${actual_result}" STREQUAL "${expected_result}")
    message(FATAL_ERROR
      "${description}: expected exit ${expected_result}, got ${actual_result}\n"
      "stdout:\n${actual_stdout}\nstderr:\n${actual_stderr}")
  endif()
  set(LAST_STDOUT "${actual_stdout}" PARENT_SCOPE)
  set(LAST_STDERR "${actual_stderr}" PARENT_SCOPE)
endfunction()

function(require_text haystack needle description)
  string(FIND "${haystack}" "${needle}" found_at)
  if(found_at EQUAL -1)
    message(FATAL_ERROR "${description}: did not find [${needle}] in:\n${haystack}")
  endif()
endfunction()

run_checked_test("help" "0" --help)
require_text("${LAST_STDOUT}" "rthtool inspect" "help output")

run_checked_test("inspect" "0" inspect "${left_file}" 4)
require_text("${LAST_STDOUT}" "Size: 10 bytes" "inspect output")
require_text("${LAST_STDOUT}" "Chunk size: 4 bytes" "inspect chunk size")

run_checked_test("compare" "0" compare "${left_file}" "${right_file}")
require_text("${LAST_STDOUT}" "Common prefix: 10 bytes" "compare output")
require_text("${LAST_STDOUT}" "Left is a prefix of right: yes" "compare prefix result")

run_checked_test("hex" "0" hex "${left_file}" 0 4)
require_text("${LAST_STDOUT}" "Hex dump:" "hex output heading")
require_text("${LAST_STDOUT}" "52 54 48 73" "hex output bytes")

run_checked_test("unknown command" "2" does-not-exist)
require_text("${LAST_STDERR}" "Unknown command: does-not-exist" "unknown command error")

run_checked_test("hex size limit" "1" hex "${left_file}" 0 1048577)
require_text("${LAST_STDERR}" "Hex dump limit is 1 MiB" "hex limit error")

run_checked_test("missing file" "1" inspect "${TEST_WORK_DIR}/missing.bin")
require_text("${LAST_STDERR}" "error:" "missing file error")

message(STATUS "rthtool CLI integration checks passed")
