cmake_minimum_required(VERSION 3.10.0)

set(LIBFUZZER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libFuzzer/bin/libFuzzer.a")

function(ImportLibFuzzer)
  add_custom_command(
    OUTPUT "${LIBFUZZER_PATH}"
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/libFuzzer/build.sh"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libFuzzer/build.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libFuzzer"
    COMMENT "Building libFuzzer..."
  )

  add_custom_target(libfuzzer_builder DEPENDS "${LIBFUZZER_PATH}")
endfunction()

function(main)
  ImportLibFuzzer()

  add_subdirectory(santacache)
  add_subdirectory(santad)
  add_subdirectory(santactl)
endfunction()

main()
