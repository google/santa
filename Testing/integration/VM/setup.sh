#!/bin/bash
# This script is manually run to (partially) setup new template VMs.

set -xeuo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

read -p "About to run visudo, set %admin ALL = (ALL) NOPASSWD: ALL"
sudo visudo

# Unpack and install xcode
if [ ! -e /Applications/Xcode.app ]; then
	(cd /Applications && xip --expand ${SCRIPT_DIR}/Xcode*.xip)
	sudo xcode-select -s /Applications/Xcode.app
	sudo xcodebuild -license accept
	# ... and open it to fixup stuff
	open /Applications/Xcode.app
fi

# Install brew
if ! command -v brew &> /dev/null; then
	/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> $HOME/.zprofile
	echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> $HOME/.bashrc
	eval "$(/opt/homebrew/bin/brew shellenv)"
fi

# Install things from brew
if ! command -v go &> /dev/null; then
	brew install bazelisk go jq
fi

# Install rosetta (for test binaries)
softwareupdate --install-rosetta --agree-to-license

# Add a LaunchAgent to start the mounted runner
cat | sudo tee ${HOME}/Library/LaunchAgents/runner.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>runner</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Volumes/init/run.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# Run sample applescript to grant bash accessibility and automation control
clang "${SCRIPT_DIR}/disclaim.c" -o /tmp/disclaim
set +e
sudo /tmp/disclaim /bin/bash "${SCRIPT_DIR}/bash_control.sh"
set -e

# Manual things for the user to do
echo "TODO:"
if csrutil status | grep -q 'System Integrity Protection status: enabled'; then
	echo "Reboot and csrutil disable"
fi

# TODO: set /etc/kcpassword to do this automatically
echo "Setup automatic login in System Preferences -> Security & Privacy"
