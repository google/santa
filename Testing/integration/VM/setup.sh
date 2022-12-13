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

# Install actions runner
mkdir ~/actions-runner
pushd ~/actions-runner
curl -o actions-runner-osx-arm64-2.296.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.296.0/actions-runner-osx-arm64-2.296.0.tar.gz
echo 'e358086b924d2e8d8abf50beec57ee7a3bb0c7d412f13abc51380f1b1894d776  actions-runner-osx-arm64-2.296.0.tar.gz' | shasum -a 256 -c
tar xzf ./actions-runner-osx-arm64-2.296.0.tar.gz
./config.sh --url https://github.com/google/santa
./svc.sh install
./svc.sh start
popd

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
