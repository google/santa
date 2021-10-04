#!/bin/bash
GIT_ROOT=$(git rev-parse --show-toplevel)

find $GIT_ROOT \( -name "*.m" -o -name "*.h" -name "*.mm" \) | xargs clang-format --Werror --dry-run

go get github.com/bazelbuild/buildtools/buildifier

~/go/bin/buildifier --lint=warn -r $GIT_ROOT
