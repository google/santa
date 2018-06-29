cmake_minimum_required(VERSION 3.10.0)
project(santactl)

function(main)
  # Include all files to make IDEs happy
  set(PROJECT_SOURCEFILES
    SNTCommand.h
    SNTCommand.m

    SNTCommandController.h
    SNTCommandController.m

    main.m

    Resources/santactl-Info.plist

    # Generic commands
    Commands/SNTCommandBundleInfo.m
    Commands/SNTCommandCheckCache.m
    Commands/SNTCommandFileInfo.m
    Commands/SNTCommandFlushCache.m
    Commands/SNTCommandRule.m
    Commands/SNTCommandStatus.m
    Commands/SNTCommandVersion.m
    Commands/SNTCommandCacheHistogram.m

    # Sync server
    Commands/sync/NSData+Zlib.h
    Commands/sync/NSData+Zlib.m

    Commands/sync/SNTCommandSync.m

    Commands/sync/SNTCommandSyncConstants.h
    Commands/sync/SNTCommandSyncConstants.m

    Commands/sync/SNTCommandSyncEventUpload.h
    Commands/sync/SNTCommandSyncEventUpload.m

    Commands/sync/SNTCommandSyncLogUpload.h
    Commands/sync/SNTCommandSyncLogUpload.m

    Commands/sync/SNTCommandSyncManager.h
    Commands/sync/SNTCommandSyncManager.m

    Commands/sync/SNTCommandSyncPostflight.h
    Commands/sync/SNTCommandSyncPostflight.m

    Commands/sync/SNTCommandSyncPreflight.h
    Commands/sync/SNTCommandSyncPreflight.m

    Commands/sync/SNTCommandSyncRuleDownload.h
    Commands/sync/SNTCommandSyncRuleDownload.m

    Commands/sync/SNTCommandSyncStage.h
    Commands/sync/SNTCommandSyncStage.m

    Commands/sync/SNTCommandSyncState.h
    Commands/sync/SNTCommandSyncState.m

    # The "common" folder contains some of the files required to build this target
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

  add_executable("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" PRIVATE -ObjC)

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
    "${CMAKE_SOURCE_DIR}/Source/santactl"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands"
    "${CMAKE_SOURCE_DIR}/Source/santactl/Commands/sync"
    "${CMAKE_SOURCE_DIR}/Source/santad"
    "${CMAKE_SOURCE_DIR}/Source/common"
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    MOLCertificate MOLCodesignChecker
    MOLAuthenticatingURLSession FMDB MOLFCMClient
    MOLXPCConnection

    "-framework Cocoa"
  )

  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT "Signing ${PROJECT_NAME} with the following identity: ${CODESIGN_IDENTITY}"
  )
endfunction()

main()
