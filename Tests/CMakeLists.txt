cmake_minimum_required(VERSION 3.10.0)

function(main)
  file(GLOB test_list LIST_DIRECTORIES true "${CMAKE_CURRENT_SOURCE_DIR}/*")

  foreach(test_path ${test_list})
    if(NOT EXISTS "${test_path}/CMakeLists.txt")
      continue()
    endif()

    if("${test_path}" STREQUAL "${CMAKE_SOURCE_DIR}/Tests/LogicTests")
      message("Not adding LogicTests (not yet supported)")
      continue()
    endif()

    message(STATUS "Adding test folder: ${test_path}")
    add_subdirectory("${test_path}")
  endforeach()
endfunction()

main()
