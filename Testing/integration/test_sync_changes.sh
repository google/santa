#!/bin/bash
set -x

bazel run //Testing/integration:install_profile -- Testing/integration/configs/default.mobileconfig
bazel run :reload --define=SANTA_BUILD_TYPE=adhoc

# Reset moroz to default config
killall moroz
~/go/bin/moroz -configs="$GITHUB_WORKSPACE/Testing/integration/configs/moroz_default/global.toml" -use-tls=false &

sudo santactl sync --debug

# Ensure baseline binary blocking
set +e
./Source/santad/testdata/binaryrules/badbinary
blocked=$?
set -e

if [[ $blocked == 0 ]]; then
  echo "Blocklisted binary allowed to run" >&2
  exit 1
fi

if [[ "$(santactl status --json | jq .daemon.block_usb)" != "false" ]]; then
  echo "USB blocking enabled with minimal config" >&2
  exit 1
fi

# Now change moroz to use the changed config, enabling USB blocking and removing the badbinary block rule
killall moroz
~/go/bin/moroz -configs="$GITHUB_WORKSPACE/Testing/integration/configs/moroz_changed/global.toml" -use-tls=false &

sudo santactl sync --debug

set +e
./Source/santad/testdata/binaryrules/badbinary
blocked=$?
set -e

if [[ $blocked != 0 ]]; then
  echo "Removal from blocklist failed" >&2
  exit 1
fi

# TODO(nickmg): USB blocking configuration changes over sync protocol are broken
# Re-enable when they're not
# if [[ "$(santactl status --json | jq .daemon.block_usb)" != "true" ]]; then
#   echo "USB blocking config change didnt take effect" >&2
#   exit 1
# fi
