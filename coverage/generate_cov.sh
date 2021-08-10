#!/bin/sh
GIT_ROOT=$(git rev-parse --show-toplevel)
PROFILE_PATH="$GIT_ROOT/CoverageData"
COV_FILE="$PROFILE_PATH/info.lcov"

function build() {
    bazel coverage \
            --test_env="LLVM_PROFILE_FILE=$PROFILE_PATH/default.profraw" \
            --experimental_use_llvm_covmap \
            --spawn_strategy=standalone \
            --cache_test_results=no \
            --test_env=LCOV_MERGER=/usr/bin/true \
            --define=SANTA_BUILD_TYPE=ci \
            //:unit_tests

    xcrun llvm-profdata merge "$PROFILE_PATH/default.profraw" -output "$PROFILE_PATH/default.profdata"
}

function generate_lcov() {
    object_files=$(find -L $(bazel info bazel-bin) -type f -exec file -L {} \; | grep "Mach-O" | sed 's,:.*,,')
    bazel_base=$(bazel info execution_root)

    true > $COV_FILE
    for file in $object_files; do
        xcrun llvm-cov export -instr-profile "$PROFILE_PATH/default.profdata" -format=lcov \
            --ignore-filename-regex="external/.*" \
          $file | sed "s,$bazel_base,$GIT_ROOT," >> $COV_FILE
    done

}

function main() {
    mkdir -p $PROFILE_PATH
    build
    generate_lcov
}
main
