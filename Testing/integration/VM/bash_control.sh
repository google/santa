#!/bin/bash
# This script adds bash to the list of programs which can control the system
# through applescript.
# It's run as part of the template VM creation process.

osascript -e 'tell application "System Settings" to activate'
osascript -e 'tell application "System Events" to tell process "System Settings" to click menu item "Profiles" of menu 1 of menu bar item "View" of menu bar 1'
