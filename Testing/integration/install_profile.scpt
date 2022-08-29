on run argv
	do shell script "open " & item 1 of argv

	delay 1

  do shell script "open '/System/Applications/System Preferences.app'"

	delay 2

	tell application "System Events"
		tell process "System Preferences"
			click menu item "Profiles" of menu 1 of menu bar item "View" of menu bar 1
			delay 2
			click button "Install…" of scroll area 1 of window "Profiles"
			delay 1
			click button "Install" of sheet 1 of window "Profiles"
		end tell
		delay 1
		tell process "SecurityAgent"
			set value of text field 2 of window 1 to system attribute "VM_PASSWORD"
			click button 2 of window 1
		end tell
	end tell

	delay 5

	tell application "System Preferences"
		quit
	end tell
end run
