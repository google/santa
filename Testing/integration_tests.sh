#!/bin/bash
set -e
set -x

GIT_ROOT=$(git rev-parse --show-toplevel)

run_tests() {
    (
        local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
        cd $GIT_ROOT/Testing/integration
        time bazel test "${TEST_FLAGS[@]}" -- ...
    )
}

setup() {
    $GIT_ROOT/Testing/start_env.sh
    sudo santactl sync --debug
}

main() {
    setup
    run_tests
}

main "$@"
