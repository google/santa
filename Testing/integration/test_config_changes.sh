#!/bin/bash
set -x

bazel run //Testing/integration:install_profile -- Testing/integration/configs/usb-block.mobileconfig
if [[ "$(santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi
