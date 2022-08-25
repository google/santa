#!/bin/bash
set -ueo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

if [[ "$(santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking already enabled?" >&2
  exit 1
fi

bazel run //Testing/integration:install_profile -- Testing/integration/configs/usb-block.mobileconfig
sleep 1

if [[ "$(santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi
