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

# Unload kext.
/sbin/kextunload -b com.google.santa-driver >/dev/null 2>&1

# Determine if anyone is logged into the GUI
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)

# Unload GUI agent if someone is logged in.
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser ${GUI_USER} /bin/launchctl remove com.google.santagui

# Cleanup cruft from old versions
/bin/launchctl remove com.google.santasync >/dev/null 2>&1
/bin/rm /Library/LaunchDaemons/com.google.santasync.plist >/dev/null 2>&1
/bin/rm /usr/libexec/santad >/dev/null 2>&1
/bin/rm /usr/sbin/santactl >/dev/null 2>&1
/bin/rm -rf /Applications/Santa.app 2>&1

# Copy new files.
/bin/cp -r ${BINARIES}/santa-driver.kext /Library/Extensions
/bin/mkdir -p /usr/local/bin
/bin/ln -s /Library/Extensions/santa-driver.kext/Contents/MacOS/santactl /usr/local/bin 2>/dev/null

if [ ! -d /var/db/santa ] ; then
  /bin/mkdir /var/db/santa
fi

/bin/cp ${CONF}/com.google.santad.plist /Library/LaunchDaemons
/bin/cp ${CONF}/com.google.santagui.plist /Library/LaunchAgents
/bin/cp ${CONF}/com.google.santa.asl.conf /etc/asl/
/bin/cp ${CONF}/com.google.santa.newsyslog.conf /etc/newsyslog.d/

# Reload syslogd to pick up ASL configuration change.
/usr/bin/killall -HUP syslogd

# Load kext.
/sbin/kextload /Library/Extensions/santa-driver.kext

# Load santad and scheduled sync jobs.
/bin/launchctl load /Library/LaunchDaemons/com.google.santad.plist

# Load GUI agent if someone is logged in.
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser ${GUI_USER} \
  /bin/launchctl load /Library/LaunchAgents/com.google.santagui.plist

exit 0
