#!/bin/bash

osascript -e 'tell application "System Preferences" to activate'
osascript -e 'tell application "System Events" to tell process "System Preferences" to click menu item "Profiles" of menu 1 of menu bar item "View" of menu bar 1'
