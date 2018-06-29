cmake_minimum_required(VERSION 3.10.0)
project(santacache_fuzzer)

set(CMAKE_CXX_STANDARD 11)

function(main)
  set(PROJECT_SOURCEFILES
    src/main.cpp
  )

  add_executable("${PROJECT_NAME}" EXCLUDE_FROM_ALL ${PROJECT_SOURCEFILES})

  add_dependencies("${PROJECT_NAME}" libfuzzer_builder)
  target_link_libraries("${PROJECT_NAME}" PRIVATE "${LIBFUZZER_PATH}")
 
  target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/common"
    "${CMAKE_SOURCE_DIR}/Source/santa-driver"
  )

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -g -O0 -Wno-deprecated-declarations
    -fsanitize-coverage=trace-pc-guard
    -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    -fsanitize=address -fno-omit-frame-pointer
    -mno-omit-leaf-frame-pointer
  )

  AddFuzzTarget("${PROJECT_NAME}" 16 60 false)
endfunction()

main()
