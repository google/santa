cmake_minimum_required(VERSION 3.10.0)

execute_process(
  COMMAND git fetch --tags --all
  COMMAND git describe --tags --always --abbrev=0
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE SANTA_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND xcode-select -p
  OUTPUT_VARIABLE DEFAULT_XCODE_ROOT_FOLDER
)

string(STRIP "${DEFAULT_XCODE_ROOT_FOLDER}" DEFAULT_XCODE_ROOT_FOLDER)

add_custom_target(tests)
function(AddTestTarget target_name run_as_root)
  if(run_as_root)
    add_custom_target(
      "${target_name}_runner"
      COMMAND sudo $<TARGET_FILE:${target_name}>
      COMMENT "Running ${target_name}_runner as root"
    )

  else()
    add_custom_target(
      "${target_name}_runner"
      COMMAND $<TARGET_FILE:${target_name}>
    )
  endif()

  add_dependencies(tests "${target_name}_runner")
endfunction()

add_custom_target(fuzz)
function(AddFuzzTarget target_name max_len max_total_time run_as_root)
  add_custom_command(TARGET "${target_name}" POST_BUILD
    COMMAND codesign --force --verify --verbose --sign "${CODESIGN_IDENTITY}" $<TARGET_FILE:${target_name}>
    COMMENT "Signing ${target_name} with the following identity: ${CODESIGN_IDENTITY}"
  )

  if(${run_as_root})
    set(sudo_command "sudo")
  else()
    set(sudo_command "")
  endif()

  add_custom_target(
    "${target_name}_runner"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/${target_name}_corpus"
    COMMAND ${sudo_command} $<TARGET_FILE:${target_name}> -max_len=${max_len} -max_total_time=${max_total_time} "${CMAKE_CURRENT_BINARY_DIR}/${target_name}_corpus" "${CMAKE_CURRENT_SOURCE_DIR}/${target_name}_seed_corpus"
    COMMENT "Running fuzzer: ${target_name}"
  )

  add_dependencies("${target_name}_runner" "${target_name}")
  add_dependencies(fuzz "${target_name}_runner")
endfunction()

function(main)
  if("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  endif()

  if(NOT DEFINED CODESIGN_IDENTITY)
    if ("$ENV{CODESIGN_IDENTITY}" STREQUAL "")
      message(FATAL_ERROR "Please define CODESIGN_IDENTITY - You can either use an environment variable or pass it to CMake with -DCODESIGN_IDENTITY=identity. If you are using sudo, make sure to keep the variable defined")
    endif()

    set(CODESIGN_IDENTITY "$ENV{CODESIGN_IDENTITY}")
  endif()

  if(NOT MACOSX_VERSION_MIN)
    set(MACOSX_VERSION_MIN 10.9)
  endif()

  if(NOT MACOSX_SDK_VERSION)
    set(sdk_version_name "Latest")
  else()
    set(sdk_version_name "${MACOSX_SDK_VERSION}")
  endif()

  if(NOT XCODE_ROOT_FOLDER)
    set(XCODE_ROOT_FOLDER "${DEFAULT_XCODE_ROOT_FOLDER}")
  endif()

  message(STATUS "MACOSX_VERSION_MIN: ${MACOSX_VERSION_MIN}")
  message(STATUS "MACOSX_SDK_VERSION: ${sdk_version_name}")
  message(STATUS "XCODE_ROOT_FOLDER: ${XCODE_ROOT_FOLDER}")
  message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
  message(STATUS "SANTA_VERSION: ${SANTA_VERSION}")

  add_subdirectory(CocoaPods)
  add_subdirectory(Source/santad)
  add_subdirectory(Source/santactl)
  add_subdirectory(Source/santabs)
  add_subdirectory(Source/SantaGUI)
  add_subdirectory(Source/santa-driver)

  add_subdirectory(Fuzzing)
  add_subdirectory(Tests)

  set(redist_folder_path "${CMAKE_BINARY_DIR}/redist")
  add_custom_command(
    OUTPUT "${redist_folder_path}/conf/install.sh"

    # Copy the binaries
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_BINARY_DIR}/Source/SantaGUI/Santa.app" "${redist_folder_path}/binaries/Santa.app"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_BINARY_DIR}/Source/santa-driver/santa-driver.kext" "${redist_folder_path}/binaries/santa-driver.kext"

    # Copy the configuration files
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_SOURCE_DIR}/Conf" "${redist_folder_path}/conf"
    COMMAND "${CMAKE_COMMAND}" -E remove_directory "${redist_folder_path}/conf/Package"
    COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_SOURCE_DIR}/Docs/deployment/com.google.santa.example.mobileconfig" "${redist_folder_path}/conf"

    COMMENT "Generating redistributable package"
  )

  add_custom_target(redist DEPENDS "${redist_folder_path}/conf/install.sh")
  add_dependencies(redist santad santa-driver santactl santabs Santa)

  install(FILES Conf/com.google.santad.plist DESTINATION /Library/LaunchDaemons)
  install(FILES Conf/com.google.santagui.plist DESTINATION /Library/LaunchAgents)

  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E echo To finalize the installation, run the following commands)")
  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E echo sudo /sbin/kextload /Library/Extensions/santa-driver.kext)")
  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E echo sudo /bin/launchctl load /Library/LaunchDaemons/com.google.santad.plist)")
  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E echo sudo /bin/launchctl asuser `/usr/bin/stat -f '%u' /dev/console` /bin/launchctl load /Library/LaunchAgents/com.google.santagui.plist)")
  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E echo Configuration guide available on ReadTheDocs - https://santa.readthedocs.io/en/latest/deployment/configuration/)")
endfunction()

main()
