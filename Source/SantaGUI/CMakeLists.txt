cmake_minimum_required(VERSION 3.10.0)
project(Santa)

function(CompileXib output_file_path_variable input_file_path)
  get_filename_component(input_file_name "${input_file_path}" NAME_WE)
  set(output_file_path "${CMAKE_CURRENT_BINARY_DIR}/${input_file_name}.nib")

  add_custom_command(
    OUTPUT "${output_file_path}"
    COMMAND ibtool --compile "${output_file_path}" "${input_file_path}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Compiling: ${input_file_path}"
  )

  set("${output_file_path_variable}" "${output_file_path}" PARENT_SCOPE)
endfunction()

# It is important to only use absolute file paths with actool
function(CompileAssets asset_file_list_variable)
  set(asset_file_list
    "${CMAKE_CURRENT_BINARY_DIR}/AppIcon.icns"
    "${CMAKE_CURRENT_BINARY_DIR}/Assets.car"
  )

  add_custom_command(
    OUTPUT ${asset_file_list}
    COMMAND xcrun actool --output-format=human-readable-text --notices --warnings --errors --platform macosx --minimum-deployment-target ${MACOSX_VERSION_MIN} --target-device mac --app-icon AppIcon --output-partial-info-plist "${CMAKE_CURRENT_BINARY_DIR}/Assets.plist" --compile "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/Resources/Images.xcassets"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Packaging resources"
  )

  set("${asset_file_list_variable}" ${asset_file_list} PARENT_SCOPE)
endfunction()

function(main)
  # Include all files to make IDEs happy
  set(PROJECT_SOURCEFILES
    SNTAboutWindowController.h
    SNTAboutWindowController.m

    SNTAccessibleTextField.h
    SNTAccessibleTextField.m

    SNTAppDelegate.h
    SNTAppDelegate.m

    SNTMessageWindow.h
    SNTMessageWindow.m

    SNTMessageWindowController.h
    SNTMessageWindowController.m

    SNTNotificationManager.h
    SNTNotificationManager.m

    main.m

    # The "common" folder contains some of the files required to build this target
    "${CMAKE_SOURCE_DIR}/Source/common/SNTConfigurator.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCControlInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCUnprivilegedControlInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTBlockMessage.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTRule.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTStoredEvent.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTSystemInfo.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCBundleServiceInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTXPCNotifierInterface.m"
    "${CMAKE_SOURCE_DIR}/Source/common/SNTLogging.m"
  )

  set(PROJECT_XIBFILES
    "${CMAKE_CURRENT_SOURCE_DIR}/Resources/AboutWindow.xib"
    "${CMAKE_CURRENT_SOURCE_DIR}/Resources/MessageWindow.xib"
  )

  foreach(xib_file ${PROJECT_XIBFILES})
    CompileXib(output_nib_file_path "${xib_file}")

    list(APPEND PROJECT_RESOURCES "${output_nib_file_path}")
    list(APPEND PROJECT_SOURCEFILES "${output_nib_file_path}")
  endforeach()

  CompileAssets(asset_file_list)
  foreach(asset_file ${asset_file_list})
    list(APPEND PROJECT_RESOURCES "${asset_file}")
    list(APPEND PROJECT_SOURCEFILES "${asset_file}")
  endforeach()

  add_executable("${PROJECT_NAME}" MACOSX_BUNDLE ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" PRIVATE -ObjC)

  set_target_properties("${PROJECT_NAME}" PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.google.SantaGUI"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Resources/SantaGUI-Info.plist"
    RESOURCE "${PROJECT_RESOURCES}"
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    MOLCertificate MOLCodesignChecker MOLXPCConnection

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
    SANTAGUI=1
  )

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions("${PROJECT_NAME}" PRIVATE DEBUG=1)
  else()
    target_compile_definitions("${PROJECT_NAME}" PRIVATE NDEBUG=1)
  endif()

  target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_SOURCE_DIR}/Source/SantaGUI"
    "${CMAKE_SOURCE_DIR}/Source/common"
    "${CMAKE_SOURCE_DIR}/Source/santad"
  )

  add_custom_command(TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" "${CMAKE_BINARY_DIR}/Source/SantaGUI/Santa.app"
    COMMENT "Signing ${PROJECT_NAME} with the following identity: ${CODESIGN_IDENTITY}"
  )

  # Ignore errors about the missing RESOURCE destination missing; this is a cmake bug
  install(TARGETS "${PROJECT_NAME}" BUNDLE DESTINATION "/Applications")
endfunction()

main()
