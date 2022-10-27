on run argv
	if application "System Preferences" is running then
		tell application "System Preferences" to quit
	end if

	delay 2

	tell application "System Events"
		tell process "UserNotificationCenter"
			click button "Open Security Preferences" of window 1
		end tell

		delay 3

		tell process "System Preferences"
			click button "Click the lock to make changes." of window "Security & Privacy"
			delay 1
			set value of text field "Password" of sheet 1 of window "Security & Privacy" to system attribute "VM_PASSWORD"
			click button "Unlock" of sheet 1 of window "Security & Privacy"
			delay 2
			click button "Allow" of tab group 1 of window "Security & Privacy"
		end tell
	end tell

	delay 2

	tell application "System Preferences" to quit

	delay 2
end run
