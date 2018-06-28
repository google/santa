cmake_minimum_required(VERSION 3.10.0)
project(santad_fuzzer)

set(CMAKE_CXX_STANDARD 11)

function(main)
  GenerateFuzzTarget(src/databaseRuleAddRules.mm 45 60 true)
  GenerateFuzzTarget(src/checkCacheForVnodeID.mm 16 60 true)
  GenerateFuzzTarget(src/databaseRemoveEventsWithIDs.mm 80 60 true)
endfunction()

function(GenerateFuzzTarget source_file data_size timeout run_as_root)
  # Generate one new project for each source file in the 'src' folder. Copy
  # the project source files and settings from santactl
  set(PROJECT_SANTACTLSOURCEFILES
    "${CMAKE_SOURCE_DIR}/Source/santactl/SNTCommand.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/SNTCommand.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/SNTCommandController.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/SNTCommandController.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Resources/santactl-Info.plist"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandBundleInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandCheckCache.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandFileInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandFlushCache.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandRule.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandStatus.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/SNTCommandVersion.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/NSData+Zlib.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/NSData+Zlib.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSync.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncConstants.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncConstants.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncEventUpload.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncEventUpload.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncLogUpload.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncLogUpload.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncManager.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncManager.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncPostflight.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncPostflight.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncPreflight.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncPreflight.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncRuleDownload.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncRuleDownload.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncStage.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncStage.m"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncState.h"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync/SNTCommandSyncState.m"

    "${CMAKE_SOURCE_DIR}/Source/common/SNTConfigurator.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTFileInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTRule.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTStoredEvent.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTSystemInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCControlInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCSyncdInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTLogging.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTDropRootPrivs.m"
  )

  get_filename_component(target_name "${source_file}" NAME_WE)
  set(target_name "santad_${target_name}_fuzzer")

  add_executable("${target_name}" EXCLUDE_FROM_ALL ${source_file} ${PROJECT_SANTACTLSOURCEFILES})

  target_compile_options("${target_name}" PRIVATE
    -fobjc-arc -Wno-everything -fmodules -fcxx-modules
    -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  target_compile_definitions("${target_name}" PRIVATE
    COCOAPODS=1
  )

  target_include_directories("${target_name}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/santactl"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync"
    "${CMAKE_SOURCE_DIR}/Source/santad"
    "${CMAKE_SOURCE_DIR}/Source/common"
  )

  target_link_libraries("${target_name}" PRIVATE
    MOLCertificate MOLCodesignChecker
    MOLAuthenticatingURLSession FMDB MOLFCMClient
    MOLXPCConnection
  )

  #
  # Add libfuzzer
  #

  add_dependencies("${target_name}" libfuzzer_builder)
  target_link_libraries("${target_name}" PRIVATE "${LIBFUZZER_PATH}")

  target_compile_options("${target_name}" PRIVATE
    -g -O0 -Wno-deprecated-declarations
    -fsanitize-coverage=trace-pc-guard
  )

  target_link_libraries("${target_name}" PRIVATE
    -fsanitize=address -fno-omit-frame-pointer
    -mno-omit-leaf-frame-pointer
  )

  AddFuzzTarget("${target_name}" ${data_size} ${timeout} ${run_as_root})
endfunction()

main()
