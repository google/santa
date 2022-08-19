#!/bin/sh

GIT_ROOT=$(git rev-parse --show-toplevel)
BAZEL_EXEC_ROOT=$(bazel info execution_root)
COV_FILE="$(bazel info output_path)/_coverage/_coverage_report.dat"

function main() {
  bazel coverage \
    --experimental_use_llvm_covmap \
    --instrument_test_targets \
    --combined_report=lcov \
    --spawn_strategy=standalone \
    --test_env=LCOV_MERGER=/usr/bin/true \
    --test_output=all \
    --jobs=1 \
    //:unit_tests

  # The generated file has most of the source files relative to bazel's
  # execution_root path, so we strip that off as it prevents files being
  # picked up by Coveralls.
  sed -i '' "s,${BAZEL_EXEC_ROOT},${GIT_ROOT}," ${COV_FILE}

  # We also want to filter out files that aren't ours but which sometimes get
  # coverage data created anyway.
  sed -i '' '/SF:\/Applications.*/,/end_of_record/d' ${COV_FILE}
  sed -i '' '/SF:.*santa\/bazel-out.*/,/end_of_record/d' ${COV_FILE}

}
main
