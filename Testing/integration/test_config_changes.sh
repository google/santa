#!/bin/bash
set -x

# TODO(nickmg): These `santactl status`s should be run with sudo to mirror the others,
# however currently (2022-10-27) non-root status is what correctly reads from provisioning profile configuration.

bazel run //Testing/integration:install_profile -- Testing/integration/configs/default.mobileconfig
if [[ "$(santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking enabled with minimal config" >&2
  exit 1
fi

bazel run //Testing/integration:install_profile -- Testing/integration/configs/usb-block.mobileconfig
if [[ "$(santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi
