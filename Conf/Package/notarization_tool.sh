#!/bin/bash

# Example NOTARIZATION_TOOL wrapper.

/usr/bin/xcrun altool --notarize-app "${2}" --primary-bundle-id "${4}" \
  -u "${NOTARIZATION_USERNAME}" -p "${NOTARIZATION_PASSWORD}"
