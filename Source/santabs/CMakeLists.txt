
cmake_minimum_required(VERSION 3.10.0)
project(santabs)

function(main)
  # Include all files to make IDEs happy
  set(PROJECT_SOURCEFILES
    SNTBundleService.h
    SNTBundleService.m
 
    main.m

    Resources/santabs-Info.plist

    # The "common" folder contains some of the files required to build this target
    "${CMAKE_SOURCE_DIR}/Source/common/SNTFileInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTStoredEvent.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCBundleServiceInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCNotifierInterface.m"
  )

  add_executable("${PROJECT_NAME}" MACOSX_BUNDLE ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" PRIVATE -ObjC)

  set_target_properties("${PROJECT_NAME}" PROPERTIES
    BUNDLE_EXTENSION "xpc"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Resources/santabs-Info.plist"
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    MOLCertificate MOLCodesignChecker
    FMDB MOLXPCConnection

    "-framework Cocoa"
  )

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -fobjc-arc -Wno-everything -fmodules
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
    "${CMAKE_SOURCE_DIR}/Source/santabs"
    "${CMAKE_SOURCE_DIR}/Source/common"
  )

  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" "${CMAKE_BINARY_DIR}/Source/santabs/santabs.xpc/Contents/MacOS/santabs"
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" "${CMAKE_BINARY_DIR}/Source/santabs/santabs.xpc"
    COMMENT "Signing ${PROJECT_NAME} with the following identity: ${CODESIGN_IDENTITY}"
  )
endfunction()

main()
