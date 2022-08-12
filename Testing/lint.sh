#!/bin/bash

function main() {
    GIT_ROOT=$(git rev-parse --show-toplevel)
    err=0

    find $GIT_ROOT \( -name "*.m" -o -name "*.h" -name "*.mm" \) -exec clang-format --Werror --dry-run {} \+
    err="$(( $err | $? ))"

    ! git grep -EIn $'[ \t]+$'
    err="$(( $err | $? ))"

    go install github.com/bazelbuild/buildtools/buildifier@latest
    ~/go/bin/buildifier --lint=warn -r $GIT_ROOT
    err="$(( $err | $? ))"
    return $err
}

main $@
exit $?
