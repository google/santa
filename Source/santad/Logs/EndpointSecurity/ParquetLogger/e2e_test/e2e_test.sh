#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd )
ROOT="$(bazel info workspace)"
TMPDIR="$(mktemp -d)"

# Go to the test directory and build the Docker image with Pandas.
pushd "${SCRIPT_DIR}" > /dev/null
docker build . -t parquet_logger_e2e_test

# Generate the test file
pushd .. > /dev/null
bazel run :write_test_file -- "${TMPDIR}/test_file.parquet"

# Run the test in a Docker container
docker run \
  --rm \
  -v "${TMPDIR}:/tmp" \
  parquet_logger_e2e_test \
  /usr/bin/env python /home/jovyan/work/check_parquet_file.py /tmp/test_file.parquet

popd > /dev/null
