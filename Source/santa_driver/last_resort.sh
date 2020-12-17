#!/bin/sh

readonly MACOS_DIR="${1}/santa-driver.kext/Contents/MacOS"
/usr/bin/lipo -remove arm64 "${MACOS_DIR}/santa-driver" \
    -output "${MACOS_DIR}/santa-driver_de-armed"
mv "${MACOS_DIR}/santa-driver_de-armed" "${MACOS_DIR}/santa-driver"

