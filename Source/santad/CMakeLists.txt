cmake_minimum_required(VERSION 3.10.0)
project(santad)

function(main)
  # Include all files to make IDEs happy
  set(PROJECT_SOURCEFILES
    SNTApplication.h
    SNTApplication.m

    SNTCachedDecision.h
    SNTCachedDecision.m

    SNTDaemonControlController.h
    SNTDaemonControlController.m

    SNTDatabaseController.h
    SNTDatabaseController.m

    SNTDriverManager.h
    SNTDriverManager.m

    SNTExecutionController.h
    SNTExecutionController.m

    SNTNotificationQueue.h
    SNTNotificationQueue.m

    SNTPolicyProcessor.h
    SNTPolicyProcessor.m

    SNTSyncdQueue.h
    SNTSyncdQueue.m

    DataLayer/SNTDatabaseTable.h
    DataLayer/SNTDatabaseTable.m

    DataLayer/SNTEventTable.h
    DataLayer/SNTEventTable.m

    DataLayer/SNTRuleTable.h
    DataLayer/SNTRuleTable.m

    Logs/SNTEventLog.h
    Logs/SNTEventLog.m

    Logs/SNTFileEventLog.h
    Logs/SNTFileEventLog.m

    Logs/SNTSyslogEventLog.h
    Logs/SNTSyslogEventLog.m

    main.m

    Resources/santad-info.plist

    # The "common" folder contains some of the files required to build this target
    "${CMAKE_SOURCE_DIR}/Source/common/SNTBlockMessage.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTFileInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTConfigurator.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTDropRootPrivs.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTRule.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTStoredEvent.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTSystemInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCBundleServiceInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCControlInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCUnprivilegedControlInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCNotifierInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCSyncdInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTLogging.m"
  )

  add_executable("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" PRIVATE -ObjC)

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
    "${CMAKE_SOURCE_DIR}/Source/santad"
    "${CMAKE_SOURCE_DIR}/Source/santad/DataLayer"
    "${CMAKE_SOURCE_DIR}/Source/santad/Logs"
    "${CMAKE_SOURCE_DIR}/Source/common"
  )

  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT "Signing ${PROJECT_NAME} with the following identity: ${CODESIGN_IDENTITY}"
  )
endfunction()

main()
