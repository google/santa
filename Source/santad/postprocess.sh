#!/bin/bash

# Move the santad binary to com.google.santa.daemon
mv "${1}/com.google.santa.daemon.systemextension/Contents/MacOS/santad" \
   "${1}/com.google.santa.daemon.systemextension/Contents/MacOS/com.google.santa.daemon"

# Move the embedded provisioning profile one-level up
mv "${1}/com.google.santa.daemon.systemextension/Contents/Resources/embedded.mobileprovision" \
   "${1}/com.google.santa.daemon.systemextension/Contents/embedded.provisionprofile" || true
