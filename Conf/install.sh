#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

if [[ -z "${BINARIES}" || -z "${CONF}" ]]; then
  if [[ -d "binaries" ]]; then
    BINARIES="${PWD}/binaries"
    CONF="${PWD}/conf"
  elif [[ -d "../binaries" ]]; then
    BINARIES="${PWD}/../binaries"
    CONF="${PWD}/../conf"
  else
    echo "Can't find binaries, run install.sh from inside the conf directory" 1>&2
    exit 1
  fi
fi

# Unload santad and scheduled sync job.
/bin/launchctl remove com.google.santad >/dev/null 2>&1

# Unload bundle service
/bin/launchctl remove com.google.santa.bundleservice >/dev/null 2>&1

# Unload kext.
/sbin/kextunload -b com.google.santa-driver >/dev/null 2>&1

# Determine if anyone is logged into the GUI
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)

# Unload GUI agent if someone is logged in.
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser ${GUI_USER} /bin/launchctl remove com.google.santagui
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser ${GUI_USER} /bin/launchctl remove com.google.santa

# Cleanup cruft from old versions
/bin/launchctl remove com.google.santasync >/dev/null 2>&1
/bin/rm /Library/LaunchDaemons/com.google.santasync.plist >/dev/null 2>&1
/bin/rm /usr/libexec/santad >/dev/null 2>&1
/bin/rm /usr/sbin/santactl >/dev/null 2>&1
/bin/rm -rf /Applications/Santa.app 2>&1
/bin/rm -rf /Library/Extensions/santa-driver.kext 2>&1

# Copy new files.
/bin/mkdir -p /var/db/santa

/bin/cp -r ${BINARIES}/Santa.app /Applications

/bin/mkdir -p /usr/local/bin
/bin/ln -s /Applications/Santa.app/Contents/MacOS/santactl /usr/local/bin 2>/dev/null

/bin/cp ${CONF}/com.google.santa.plist /Library/LaunchAgents
/bin/cp ${CONF}/com.google.santa.bundleservice.plist /Library/LaunchDaemons
/bin/cp ${CONF}/com.google.santa.asl.conf /etc/asl/
/bin/cp ${CONF}/com.google.santa.newsyslog.conf /etc/newsyslog.d/

# Reload syslogd to pick up ASL configuration change.
/usr/bin/killall -HUP syslogd

# Only copy the kext and load santad if running pre-10.15
if [ $(uname -r | cut -d'.' -f1) -lt 19 ]; then
  /bin/cp -r ${BINARIES}/santa-driver.kext /Library/Extensions
  /bin/cp ${CONF}/com.google.santad.plist /Library/LaunchDaemons
  /bin/launchctl load /Library/LaunchDaemons/com.google.santad.plist
else
  /Applications/Santa.app/Contents/MacOS/Santa --load-system-extension
fi

# Load the bundle service
/bin/launchctl load /Library/LaunchDaemons/com.google.santa.bundleservice.plist

# Load GUI agent if someone is logged in.
if [[ -n "$GUI_USER" ]]; then
  /bin/launchctl asuser ${GUI_USER} \
  /bin/launchctl load -w /Library/LaunchAgents/com.google.santa.plist
fi

exit 0
