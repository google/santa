#!/bin/bash
GIT_ROOT=$(git rev-parse --show-toplevel)

find $GIT_ROOT \( -name "*.m" -o -name "*.h" -name "*.mm" \) | xargs clang-format -i
buildifier --lint=fix -r $GIT_ROOT
