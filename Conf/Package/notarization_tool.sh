#!/bin/bash

# Example NOTARIZATION_TOOL wrapper.

/usr/bin/xcrun notarytool submit "${2}" --wait \
  --apple-id "${NOTARIZATION_USERNAME}" --password "${NOTARIZATION_PASSWORD}"
