#!/bin/sh

# TODO: Pull benchmarks from previous commit to check for regression
bazel test //:benchmarks --define=SANTA_BUILD_TYPE=ci
