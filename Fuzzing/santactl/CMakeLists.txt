cmake_minimum_required(VERSION 3.10.0)
project(santactl_fuzzer)

set(CMAKE_CXX_STANDARD 11)

function(main)
  set(PROJECT_SOURCEFILES
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncRuleDownload.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncConstants.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncStage.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncState.m"

    "${CMAKE_SOURCE_DIR}/Source/common/SNTRule.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTLogging.m"

    src/main.mm
  )

  add_executable("${PROJECT_NAME}" EXCLUDE_FROM_ALL ${PROJECT_SOURCEFILES})

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -fobjc-arc -Wno-everything -fmodules -fcxx-modules
    -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  target_compile_definitions("${PROJECT_NAME}" PRIVATE
    COCOAPODS=1
  )

  target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync"
    "${CMAKE_SOURCE_DIR}/Source/common"
    "${CMAKE_SOURCE_DIR}/Source/santad"
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    MOLCertificate MOLCodesignChecker
    MOLAuthenticatingURLSession FMDB MOLFCMClient
  )

  #
  # Add libfuzzer
  #

  add_dependencies("${PROJECT_NAME}" libfuzzer_builder)
  target_link_libraries("${PROJECT_NAME}" PRIVATE "${LIBFUZZER_PATH}")

  target_compile_options("${PROJECT_NAME}" PRIVATE
    -g -O0 -Wno-deprecated-declarations
    -fsanitize-coverage=trace-pc-guard
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    -fsanitize=address -fno-omit-frame-pointer
    -mno-omit-leaf-frame-pointer
  )

  AddFuzzTarget("${PROJECT_NAME}" 428 60 false)
endfunction()

main()
