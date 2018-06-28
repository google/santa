cmake_minimum_required(VERSION 3.10.0)
project(santa-driver)

set(CMAKE_CXX_STANDARD 11)

function(main)
  # Include all files to make IDEs happy
  set(PROJECT_INFOPLIST "${CMAKE_CURRENT_SOURCE_DIR}/Resources/santa-driver-Info.plist")

  set(PROJECT_SOURCEFILES
    SantaCache.h

    SantaDecisionManager.cc
    SantaDecisionManager.h

    SantaDriver.cc
    SantaDriver.h

    SantaDriverClient.cc
    SantaDriverClient.h

    main.c

    "${PROJECT_INFOPLIST}"
  )

  add_library("${PROJECT_NAME}" MODULE ${PROJECT_SOURCEFILES})
  set_target_properties("${PROJECT_NAME}" PROPERTIES
    BUNDLE TRUE
    BUNDLE_EXTENSION "kext"
    MACOSX_BUNDLE_INFO_PLIST "${PROJECT_INFOPLIST}"
  )

  # As we have to include the executables in the same bundle, make sure
  # we add them as dependencies
  add_dependencies("${PROJECT_NAME}" santad santactl santabs)

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -fmessage-length=0 -fdiagnostics-show-note-include-stack -fmacro-backtrace-limit=0
    -nostdinc -fmodules -gmodules -fno-builtin -Wno-trigraphs -msoft-float -O0 -fno-common
    -fapple-kext -fasm-blocks -fstrict-aliasing -MMD -MT dependencies
    -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options("${PROJECT_NAME}" PRIVATE -g3)
  endif()

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -Wnon-modular-include-in-framework-module -Werror=non-modular-include-in-framework-module
    -Wno-missing-field-initializers -Wno-missing-prototypes -Werror=return-type -Wdocumentation
    -Wunreachable-code -Werror=deprecated-objc-isa-usage -Werror=objc-root-class -Wno-missing-braces
    -Wparentheses -Wswitch -Wunused-function -Wno-unused-label -Wno-unused-parameter
    -Wunused-variable -Wunused-value -Wempty-body -Wuninitialized -Wconditional-uninitialized
    -Wno-unknown-pragmas -Wno-shadow -Wno-four-char-constants -Wno-conversion -Wconstant-conversion
    -Wint-conversion -Wbool-conversion -Wenum-conversion -Wno-float-conversion
    -Wnon-literal-null-conversion -Wobjc-literal-conversion -Wshorten-64-to-32 -Wpointer-sign
    -Wno-newline-eof -Wdeprecated-declarations -Wno-sign-conversion -Winfinite-recursion -Wcomma
    -Wblock-capture-autoreleasing -Wstrict-prototypes -Wunguarded-availability
  )

  target_compile_definitions("${PROJECT_NAME}" PRIVATE
    KERNEL
    KERNEL_PRIVATE
    DRIVER_PRIVATE
    APPLE
    NeXT
    CMAKE
    -DSANTA_VERSION="${SANTA_VERSION}"
  )

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions("${PROJECT_NAME}" PRIVATE DEBUG)
  else()
    target_compile_definitions("${PROJECT_NAME}" PRIVATE NDEBUG)
  endif()

  target_include_directories("${PROJECT_NAME}" SYSTEM PRIVATE
    "${XCODE_ROOT_FOLDER}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX${MACOSX_SDK_VERSION}.sdk/System/Library/Frameworks/Kernel.framework/PrivateHeaders"
    "${XCODE_ROOT_FOLDER}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX${MACOSX_SDK_VERSION}.sdk/System/Library/Frameworks/Kernel.framework/Headers"
  )

  target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/santa-driver"
    "${CMAKE_SOURCE_DIR}/Source/common"
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    -Xlinker -export_dynamic
    -Xlinker -no_deduplicate
    -Xlinker -kext
    -nostdlib -lkmodc++ -lkmod -lcc_kext
  )

  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    # Copy santad and santactl
    COMMAND "${CMAKE_COMMAND}" -E copy $<TARGET_FILE:santad> "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.kext/Contents/MacOS"
    COMMAND "${CMAKE_COMMAND}" -E copy $<TARGET_FILE:santactl> "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.kext/Contents/MacOS"

    # Copy the the santabs service
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_BINARY_DIR}/Source/santabs/santabs.xpc" "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.kext/Contents/XPCServices/santabs.xpc"

    # Sign everything
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" "${CMAKE_BINARY_DIR}/Source/santa-driver/santa-driver.kext"
    COMMENT "Building and signing santa-driver.kext"
  )

  install(TARGETS "${PROJECT_NAME}" LIBRARY DESTINATION "/Library/Extensions")
  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink /Library/Extensions/santa-driver.kext/Contents/MacOS/santactl /usr/local/bin/santactl)")
endfunction()

main()
