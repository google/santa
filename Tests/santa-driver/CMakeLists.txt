cmake_minimum_required(VERSION 3.10.0)
project(santa-driver-test)

function(main)
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_GNU_EXTENSIONS OFF)

  # Include all files to make IDEs happy
  set(PROJECT_SOURCEFILES
    main.mm

    "${CMAKE_SOURCE_DIR}/Source/santad/SNTDriverManager.h"
    "${CMAKE_SOURCE_DIR}/Source/santad/SNTDriverManager.m"

    "${CMAKE_SOURCE_DIR}/Source/common/SNTLogging.m"
  )

  add_executable("${PROJECT_NAME}" EXCLUDE_FROM_ALL ${PROJECT_SOURCEFILES})
  AddTestTarget("${PROJECT_NAME}" true)

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    -ObjC "-framework Cocoa"
  )

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -fobjc-arc -Wno-everything -fmodules -fcxx-modules
    -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options("${PROJECT_NAME}" PRIVATE -g3)
  endif()

  target_compile_definitions("${PROJECT_NAME}" PRIVATE
    COCOAPODS=1
  )

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions("${PROJECT_NAME}" PRIVATE DEBUG=1)
  else()
    target_compile_definitions("${PROJECT_NAME}" PRIVATE NDEBUG=1)
  endif()

  target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/santad"
    "${CMAKE_SOURCE_DIR}/Source/common"
  )

  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT "Signing ${PROJECT_NAME} with the following identity: ${CODESIGN_IDENTITY}"
  )
endfunction()

main()
