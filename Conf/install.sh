#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

if [[ -d "binaries" ]]; then
  SOURCE="."
elif [[ -d "../binaries" ]]; then
  SOURCE=".."
else
  echo "Can't find binaries, run install.sh from inside the conf directory" 1>&2
  exit 1
fi

# Determine if anyone is logged into the GUI
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)

# Unload santad and scheduled sync job.
/bin/launchctl remove com.google.santad >/dev/null 2>&1

# Unload kext.
/sbin/kextunload -b com.google.santa-driver >/dev/null 2>&1

# Unload GUI agent if someone is logged in.
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser ${GUI_USER} /bin/launchctl remove /Library/LaunchAgents/com.google.santagui.plist

# Cleanup cruft from old versions
/bin/launchctl remove com.google.santasync >/dev/null 2>&1
/bin/rm /Library/LaunchDaemons/com.google.santasync.plist >/dev/null 2>&1
/bin/rm /usr/libexec/santad >/dev/null 2>&1
/bin/rm /usr/sbin/santactl >/dev/null 2>&1

# Copy new files.
/bin/cp -r ${SOURCE}/binaries/santa-driver.kext /Library/Extensions
/bin/cp -r ${SOURCE}/binaries/Santa.app /Applications
mkdir -p /usr/local/bin
/bin/ln -s /Library/Extensions/santa-driver.kext/Contents/MacOS/santactl /usr/local/bin

/bin/cp ${SOURCE}/conf/com.google.santad.plist /Library/LaunchDaemons
/bin/cp ${SOURCE}/conf/com.google.santagui.plist /Library/LaunchAgents
/bin/cp ${SOURCE}/conf/com.google.santa.asl.conf /etc/asl/

# Reload syslogd to pick up ASL configuration change.
/usr/bin/killall -HUP syslogd

# Load kext.
/sbin/kextload /Library/Extensions/santa-driver.kext

# Load santad and scheduled sync jobs.
/bin/launchctl load /Library/LaunchDaemons/com.google.santad.plist

# Load GUI agent if someone is logged in.
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser ${GUI_USER} /bin/launchctl load /Library/LaunchAgents/com.google.santagui.plist

exit 0
