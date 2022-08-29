#!/bin/bash
set -ueo pipefail

if [[ "$(santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking already enabled?" >&2
  exit 1
fi

osascript Testing/integration/install_profile.scpt Testing/integration/configs/usb-block.mobileconfig
sleep 1

if [[ "$(santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi
