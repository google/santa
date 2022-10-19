#!/bin/bash
set -x

bazel run //Testing/integration:install_profile -- Testing/integration/configs/default.mobileconfig
bazel run :reload --define=SANTA_BUILD_TYPE=adhoc

sudo santactl sync --debug
if [[ "$(santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking enabled with minimal config" >&2
  exit 1
fi

killall moroz
~/go/bin/moroz -configs="$GITHUB_WORKSPACE/Testing/integration/configs/moroz_changed/global.toml" -use-tls=false &

sudo santactl sync --debug
if [[ "$(santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
  echo "USB blocking config change didnt take effect" >&2
  exit 1
fi

set +e
./Source/santad/testdata/binaryrules/badbinary
previously_blocklisted=$?
set -e

if [[ $previously_blocklisted != 0 ]]; then
  echo "Removal from blocklist failed" >&2
  exit 1
fi
