#!/bin/bash
set -eu

function main() {
    GIT_ROOT=$(git rev-parse --show-toplevel)

    find $GIT_ROOT \( -name "*.m" -o -name "*.h" -name "*.mm" \) -exec clang-format --Werror --dry-run {} \+

    go get github.com/bazelbuild/buildtools/buildifier
    ~/go/bin/buildifier --lint=warn -r $GIT_ROOT
}

main $@
exit $?
