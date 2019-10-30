#!/bin/bash

# Move the santad binary to com.google.santa.daemon
mv "${1}/com.google.santa.daemon.systemextension/Contents/MacOS/santad" \
   "${1}/com.google.santa.daemon.systemextension/Contents/MacOS/com.google.santa.daemon"
