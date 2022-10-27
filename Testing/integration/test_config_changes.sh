#!/bin/bash
set -x

bazel run //Testing/integration:install_profile -- Testing/integration/configs/default.mobileconfig
sleep 3
if [[ "$(sudo santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking enabled with minimal config" >&2
  exit 1
fi

bazel run //Testing/integration:install_profile -- Testing/integration/configs/usb-block.mobileconfig
sleep 3
if [[ "$(sudo santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi
