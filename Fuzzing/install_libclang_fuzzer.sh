#!/bin/bash
# Xcode doesn't include the fuzzer runtime, but the one LLVM ships is compatible with Apple clang.
set -uexo pipefail

CLANG_VERSION=$(clang --version | head -n 1 | cut -d' ' -f 4)
DST_PATH="$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/${CLANG_VERSION}/lib/darwin/libclang_rt.fuzzer_osx.a"

if [ -f ${DST_PATH} ]; then
  exit 0;
fi

curl -O -L https://github.com/llvm/llvm-project/releases/download/llvmorg-${CLANG_VERSION}/clang+llvm-${CLANG_VERSION}-x86_64-apple-darwin.tar.xz
tar xvf clang+llvm-${CLANG_VERSION}-x86_64-apple-darwin.tar.xz clang+llvm-${CLANG_VERSION}-x86_64-apple-darwin/lib/clang/${CLANG_VERSION}/lib/darwin/libclang_rt.fuzzer_osx.a
cp clang+llvm-${CLANG_VERSION}-x86_64-apple-darwin/lib/clang/${CLANG_VERSION}/lib/darwin/libclang_rt.fuzzer_osx.a ${DST_PATH}
