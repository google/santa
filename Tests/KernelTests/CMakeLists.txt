cmake_minimum_required(VERSION 3.10.0)
project(KernelTests)

set(CMAKE_CXX_STANDARD 11)

function(main)
  # Include all files to make IDEs happy
  set(PROJECT_SOURCEFILES
    main.mm
  )

  add_executable("${PROJECT_NAME}" EXCLUDE_FROM_ALL ${PROJECT_SOURCEFILES})
  AddTestTarget("${PROJECT_NAME}" true)

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -fobjc-arc -Wno-everything -fmodules
    -fcxx-modules -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions("${PROJECT_NAME}" PRIVATE DEBUG=1)
  else()
    target_compile_definitions("${PROJECT_NAME}" PRIVATE NDEBUG=1)
  endif()

  target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/common"
  )
endfunction()

main()
