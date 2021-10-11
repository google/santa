#!/bin/bash

function main() {
    err=0
    GIT_ROOT=$(git rev-parse --show-toplevel)

    find $GIT_ROOT \( -name "*.m" -o -name "*.h" -name "*.mm" \) | xargs clang-format --Werror --dry-run
    err="$(( $err | $? ))"

    go get github.com/bazelbuild/buildtools/buildifier
    ~/go/bin/buildifier --lint=warn -r $GIT_ROOT
    err="$(( $err | $? ))"
    return $err
}

main $@
exit $?
