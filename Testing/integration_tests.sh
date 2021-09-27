#!/bin/bash
set -e
set -x


run_tests() {
    local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
    cd ./integration
    time bazel test "${TEST_FLAGS[@]}" -- ...
}

setup() {
    ./start_env.sh
    sudo santactl sync --debug
}

main() {
    setup
    run_tests
}

main "$@"
