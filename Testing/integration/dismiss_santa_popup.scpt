-- Dismiss the "blocked execution" popup from Santa.
-- This is run inside test VMs.

on run argv
	tell application "System Events"
		tell process "Santa"
            click button "Ignore" of window 1
        end tell
    end tell
end run
