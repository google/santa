#!/bin/bash
set -xe

bazel run //Testing/integration:install_profile -- Testing/integration/configs/default.mobileconfig
sudo diskutil unmount force USB || true

killall moroz
/tmp/moroz -configs="$GITHUB_WORKSPACE/Testing/integration/configs/moroz_default/global.toml" -use-tls=false &
sudo santactl sync --debug
if [[ "$(sudo santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking enabled with minimal config" >&2
  exit 1
fi

sudo diskutil mount USB
echo test > /Volumes/USB/test
sync
sudo diskutil unmount force USB

killall moroz
/tmp/moroz -configs="$GITHUB_WORKSPACE/Testing/integration/configs/moroz_changed/global.toml" -use-tls=false &
sudo santactl sync --debug
if [[ "$(sudo santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi

set +e
sudo diskutil mount USB
blocked=$?
set -e

if [[ $blocked == 0 ]]; then
  echo "R/W mount succeeded with USB blocking enabled" >&2
  exit 1
fi

sleep 5

# Santa should have remounted the disk RO for us. Check that it did.
bazel run //Testing/integration:dismiss_usb_popup
cat /Volumes/USB/test

sudo diskutil unmount force USB

# Ensure things can still be normally mounted if mount flags match remount opts.
set +e
sudo diskutil mount -mountOptions ro,noexec USB
blocked=$?
set -e

if [[ $blocked != 0 ]]; then
  echo "RO+noexec mount failed with USB blocking enabled" >&2
  exit 1
fi
