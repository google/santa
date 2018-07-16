#!/usr/bin/env bash

LLVM_VERSION='5.0.1'
LLVM_COMPILERRT_TARBALL_NAME="llvm-${LLVM_VERSION}.src.tar.xz"
LLVM_COMPILERRT_SRC_FOLDER_NAME=`echo "${LLVM_COMPILERRT_TARBALL_NAME}" | cut -d '.' -f 1-4`
LLVM_COMPILERRT_TARBALL_URL="http://releases.llvm.org/${LLVM_VERSION}/${LLVM_COMPILERRT_TARBALL_NAME}"

LIBFUZZER_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_FILE=`mktemp`

main() {
  echo "libFuzzer build script"

  echo " > Checking dependencies..."
  checkDependencies || return 1

  echo " > Entering libFuzzer folder..."
  cd "${LIBFUZZER_FOLDER}" > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    echo "Failed to enter the libFuzzer folder: ${LIBFUZZER_FOLDER}"
    return 1
  fi

  if [ ! -f "${LLVM_COMPILERRT_TARBALL_NAME}" ] ; then
    echo " > Downloading the LLVM tarball..."
    curl "${LLVM_COMPILERRT_TARBALL_URL}" -o "${LLVM_COMPILERRT_TARBALL_NAME}" > "${LOG_FILE}" 2>&1
    if [ $? -ne 0 ] ; then
      dumpLogFile "Failed to download the LLVM tarball"
      return 1
    fi
  else
    echo " > An existing LLVM tarball was found"
  fi

  if [ -d "${LLVM_COMPILERRT_SRC_FOLDER_NAME}" ] ; then
    echo " > Deleting existing LLVM folder..."
    rm -rf "${LLVM_COMPILERRT_SRC_FOLDER_NAME}" > "${LOG_FILE}" 2>&1
    if [ $? -ne 0 ] ; then
      dumpLogFile "Failed to delete the existing source folder"
      return 1
    fi
  fi

  echo " > Extracting the LLVM tarball..."
  tar xf "${LLVM_COMPILERRT_TARBALL_NAME}" > "${LOG_FILE}" 2>&1
  if [ $? -ne 0 ] ; then
    rm "${LLVM_COMPILERRT_TARBALL_NAME}" "${LLVM_COMPILERRT_SRC_FOLDER_NAME}"
    dumpLogFile "Failed to extract the LLVM tarball"
    return 1
  fi

  if [ -d "bin" ] ; then
    echo " > Deleting existing bin folder..."
    rm -rf "bin" > "${LOG_FILE}" 2>&1
    if [ $? -ne 0 ] ; then
      dumpLogFile "Failed to delete the existing bin folder"
      return 1
    fi
  fi

  mkdir "bin" > "${LOG_FILE}" 2>&1
  if [ $? -ne 0 ] ; then
    dumpLogFile "Failed to create the bin folder"
    return 1
  fi

  echo " > Building libFuzzer..."
  ( cd "bin" && "../${LLVM_COMPILERRT_SRC_FOLDER_NAME}/lib/Fuzzer/build.sh" ) > "${LOG_FILE}" 2>&1
  if [ $? -ne 0 ] ; then
    dumpLogFile "Failed to build the library"
    return 1
  fi

  printf "\nFinished building libFuzzer\n"
  rm "${LOG_FILE}"

  return 0
}

checkDependencies() {
  executable_list=( "clang++" "curl" "tar" )

  for executable in "${executable_list[@]}" ; do
    which "${executable}" > /dev/null 2>&1
    if [ $? -ne 0 ] ; then
      echo "The following program was not found: ${executable}"
      return 1
    fi
  done

  return 0
}

dumpLogFile() {
  if [ $# -eq 1 ] ; then
    local message="$1"
  else
    local message="An error has occurred"
  fi

  printf "${message}\n"
  printf "Log file follows\n===\n"
  cat "${LOG_FILE}"
  printf "\n===\n"
  rm "${LOG_FILE}"
}

main $@
exit $?
