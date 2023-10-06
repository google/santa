-- Allows the Santa system extension in System Settings.
-- This is run inside test VMs.

on run argv
	if application "System Settings" is running then
		tell application "System Settings" to quit
	end if

	delay 2

	tell application "System Events"
		tell process "UserNotificationCenter"
			click button "Open System Settings" of window 1
		end tell

		delay 3

		tell process "System Settings"
            -- Click the "Allow" under "system software ... was blocked from loading"
            click button 1 of group 5 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1
            delay 2
			set value of text field 2 of sheet 1 of window 1 to system attribute "VM_PASSWORD"
			click button 1 of sheet 1 of window 1
		end tell
	end tell

	delay 2

	tell application "System Settings" to quit

	delay 2
end run
