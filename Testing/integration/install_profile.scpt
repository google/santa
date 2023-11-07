-- Installs the passed profile (.mobileconfig).
-- This is run inside test VMs, primarily to configure Santa.
-- macOS 13+ only due to changes in system settings/preferences scripting.

on run argv
	tell application "System Settings" to activate

	delay 2

	tell application "System Events"
		tell process "System Settings"
			click menu item "Profiles" of menu 1 of menu bar item "View" of menu bar 1
			delay 3
			-- Thanks SwiftUI.
			-- Press the +
			click button 1 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1
			delay 2
			-- Cmd+Shift+G to select file
			keystroke "G" using {command down, shift down}
			delay 2
			-- Type in the profile we want, and return to exit the "go to" sheet
			keystroke item 1 of argv
			keystroke return
			delay 2
			-- Return to choose the file
			keystroke return
			delay 2
			-- Are you sure? Press continue
			click button 2 of group 1 of sheet 1 of window 1
			delay 2
			-- Press install
			click button "Install" of sheet 1 of window 1
		end tell
		delay 5
		tell process "SecurityAgent"
			set value of text field 2 of window 1 to system attribute "VM_PASSWORD"
			click button 2 of window 1
		end tell
	end tell

	delay 5

	tell application "System Settings" to quit

	delay 2
end run
