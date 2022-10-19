on run argv
	tell application "System Preferences"
		activate
	end tell

	delay 2

	tell application "System Preferences"
		activate
	end tell

	delay 2

	tell application "System Events"
		tell process "System Preferences"
			click menu item "Security & Privacy" of menu 1 of menu bar item "View" of menu bar 1
			delay 3
			click button "Click the lock to make changes." of window "Security & Privacy"
			delay 1
			set value of text field "Password" of sheet 1 of window "Security & Privacy" to system attribute "VM_PASSWORD"
			click button "Unlock" of sheet 1 of window "Security & Privacy"
			delay 2
			click button "Allow" of tab group 1 of window "Security & Privacy"
		end tell
	end tell

	delay 2

	tell application "System Preferences"
		quit
	end tell

	delay 2
end run
