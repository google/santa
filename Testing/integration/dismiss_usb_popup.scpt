-- Dismiss the "disk remounted" popup from Santa.
-- This is run inside test VMs.

on run argv
	tell application "System Events"
		tell process "Santa"
            click button 1 of group 1 of window 1
        end tell
    end tell
end run
