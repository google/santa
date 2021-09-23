#!/bin/sh
killall moroz
security delete-identity -c "localhost"
rm -rf /Applications/Santa.app
systemextensionsctl reset
