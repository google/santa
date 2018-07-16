cmake_minimum_required(VERSION 3.10.0)
project(CocoaPods)

function(main)
  add_custom_command(
    OUTPUT "${CMAKE_SOURCE_DIR}/Pods/Manifest.lock"
    COMMAND pod repo update && pod install
    DEPENDS "${CMAKE_SOURCE_DIR}/Podfile"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Fetching CocoaPods dependencies"
    VERBATIM
  )

  add_custom_target("${PROJECT_NAME}"
    DEPENDS "${CMAKE_SOURCE_DIR}/Pods/Manifest.lock"
  )

  ImportCocoaPodsLibrary(
    FMDB
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb"

    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabase.h"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMResultSet.h"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabasePool.h"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabaseQueue.h"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDB.h"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabaseAdditions.h"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabaseQueue.m"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabaseAdditions.m"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabase.m"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMDatabasePool.m"
    "${CMAKE_SOURCE_DIR}/Pods/FMDB/src/fmdb/FMResultSet.m"
  )

  target_link_libraries(FMDB PUBLIC sqlite3 "-framework Cocoa")

  ImportCocoaPodsLibrary(
    MOLCertificate
    "${CMAKE_SOURCE_DIR}/Pods/MOLCertificate/Source/MOLCertificate"

    "${CMAKE_SOURCE_DIR}/Pods/MOLCertificate/Source/MOLCertificate/MOLCertificate.m"
    "${CMAKE_SOURCE_DIR}/Pods/MOLCertificate/Source/MOLCertificate/MOLCertificate.h"
  )

  target_link_libraries(MOLCertificate PUBLIC "-framework Security" "-framework Cocoa")

  ImportCocoaPodsLibrary(
    MOLCodesignChecker
    "${CMAKE_SOURCE_DIR}/Pods/MOLCodesignChecker/Source/MOLCodesignChecker"

    "${CMAKE_SOURCE_DIR}/Pods/MOLCodesignChecker/Source/MOLCodesignChecker/MOLCodesignChecker.h"
    "${CMAKE_SOURCE_DIR}/Pods/MOLCodesignChecker/Source/MOLCodesignChecker/MOLCodesignChecker.m"
  )

  target_link_libraries(MOLCodesignChecker PUBLIC "-framework Security" "-framework Cocoa")

  ImportCocoaPodsLibrary(
    MOLAuthenticatingURLSession
    "${CMAKE_SOURCE_DIR}/Pods/MOLAuthenticatingURLSession/Source/MOLAuthenticatingURLSession"

    "${CMAKE_SOURCE_DIR}/Pods/MOLAuthenticatingURLSession/Source/MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.m"
    "${CMAKE_SOURCE_DIR}/Pods/MOLAuthenticatingURLSession/Source/MOLAuthenticatingURLSession/MOLDERDecoder.m"
    "${CMAKE_SOURCE_DIR}/Pods/MOLAuthenticatingURLSession/Source/MOLAuthenticatingURLSession/MOLDERDecoder.h"
    "${CMAKE_SOURCE_DIR}/Pods/MOLAuthenticatingURLSession/Source/MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h"
  )

  target_link_libraries(MOLAuthenticatingURLSession PUBLIC "-framework Security" MOLCertificate "-framework Cocoa")

  ImportCocoaPodsLibrary(
    MOLFCMClient
    "${CMAKE_SOURCE_DIR}/Pods/MOLFCMClient/MOLFCMClient"

    "${CMAKE_SOURCE_DIR}/Pods/MOLFCMClient/Source/MOLFCMClient/MOLFCMClient.m"
    "${CMAKE_SOURCE_DIR}/Pods/MOLFCMClient/Source/MOLFCMClient/MOLFCMClient.h"
  )

  target_link_libraries(MOLFCMClient PUBLIC MOLCertificate MOLAuthenticatingURLSession "-framework Cocoa")
  target_compile_options(MOLFCMClient PRIVATE -fobjc-weak)

  ImportCocoaPodsLibrary(
    MOLXPCConnection
    "${CMAKE_SOURCE_DIR}/Pods/MOLXPCConnection/Source/MOLXPCConnection"

    "${CMAKE_SOURCE_DIR}/Pods/MOLXPCConnection/Source/MOLXPCConnection/MOLXPCConnection.h"
    "${CMAKE_SOURCE_DIR}/Pods/MOLXPCConnection/Source/MOLXPCConnection/MOLXPCConnection.m"
  )

  target_link_libraries(MOLXPCConnection PUBLIC "-framework Cocoa")

  ImportCocoaPodsLibrary(
    OCMock
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock"

    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMExceptionReturnValueProvider.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMBlockCaller.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMExpectationRecorder.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMockObject.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMArgAction.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMMacroState.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMRealObjectForwarder.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMInvocationStub.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCPartialMockObject.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMock.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMStubRecorder.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMRecorder.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMInvocationExpectation.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMFunctions.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMIndirectReturnValueProvider.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCProtocolMockObject.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMBlockArgCaller.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMReturnValueProvider.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMBoxedReturnValueProvider.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCClassMockObject.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSObject+OCMAdditions.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMInvocationMatcher.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMPassByRefSetter.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMArg.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSNotificationCenter+OCMAdditions.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMObserverRecorder.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMNotificationPoster.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMVerifier.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMConstraint.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMLocation.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSInvocation+OCMAdditions.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSValue+OCMAdditions.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCObserverMockObject.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSMethodSignature+OCMAdditions.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMRealObjectForwarder.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMMacroState.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMArgAction.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMockObject.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMExpectationRecorder.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMBlockCaller.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMExceptionReturnValueProvider.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMIndirectReturnValueProvider.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMFunctions.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMStubRecorder.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMRecorder.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMInvocationExpectation.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCPartialMockObject.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMInvocationStub.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMPassByRefSetter.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMInvocationMatcher.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSObject+OCMAdditions.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCClassMockObject.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMBoxedReturnValueProvider.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMBlockArgCaller.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMReturnValueProvider.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCProtocolMockObject.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSMethodSignature+OCMAdditions.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMFunctionsPrivate.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSInvocation+OCMAdditions.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCObserverMockObject.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSValue+OCMAdditions.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMLocation.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMConstraint.h"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMVerifier.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMNotificationPoster.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMObserverRecorder.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/NSNotificationCenter+OCMAdditions.m"
    "${CMAKE_SOURCE_DIR}/Pods/OCMock/Source/OCMock/OCMArg.h"
  )

  target_link_libraries(OCMock PUBLIC "-framework Cocoa")
  target_compile_options(OCMock PRIVATE -fno-objc-arc)
endfunction()

function(ImportCocoaPodsLibrary library_name source_directory)
	set_source_files_properties(${ARGN} PROPERTIES GENERATED True)

  add_library("${library_name}" STATIC ${ARGN})
  add_dependencies("${library_name}" "${PROJECT_NAME}")

  target_include_directories("${library_name}" PUBLIC
    "${source_directory}"
    "${CMAKE_SOURCE_DIR}/Pods/Headers/Public"
  )

  target_compile_options("${library_name}" PUBLIC
    -Wno-deprecated -fmodules -fcxx-modules -fobjc-arc
    -mmacosx-version-min=${MACOSX_VERSION_MIN}
  )

  if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo" OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options("${library_name}" PRIVATE -g3)
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options("${library_name}" PRIVATE -O0)
  else()
    target_compile_options("${library_name}" PRIVATE -O3)
  endif()
endfunction()

main()
