#!/bin/bash

# Move the embedded provisioning profile one-level up
mv "${1}/Santa.app/Contents/Resources/embedded.mobileprovision" \
   "${1}/Santa.app/Contents/embedded.provisionprofile" || true
