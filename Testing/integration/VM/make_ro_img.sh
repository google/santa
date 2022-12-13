#!/bin/bash
# This script is manually run to create a read-only disk image
# which is mounted into new VMs to help automate the setup process.

set -xeuo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ $# -ne 2 ]; then
	echo "Usage: $0 image_path xcode_xip_path" >&2
	exit 1
fi

IMG=$1
XCODE=$2

MOUNT_PATH="/Volumes/RO"

hdiutil create -size 40G -fs APFS -volname RO "${IMG}"
hdiutil attach "${IMG}"

cp "${XCODE}" "${MOUNT_PATH}"
cp "${SCRIPT_DIR}"/{setup.sh,disclaim.c,bash_control.sh} "${MOUNT_PATH}"

hdiutil detach "${MOUNT_PATH}"
