#!/bin/bash

# Uninstalls Santa from the boot volume, clearing up everything but logs/configs.
# Unloads the kernel extension, services, and deletes component files.
# If a user is logged in, also unloads the GUI agent.

[ "$EUID" != 0 ] && printf "%s\n" "This requires running as root/sudo." && exit 1

/bin/launchctl remove com.google.santad
sleep 1
/sbin/kextunload -b com.google.santa-driver >/dev/null 2>&1
user=$(/usr/bin/stat -f '%u' /dev/console)
[[ -n "$user" ]] && /bin/launchctl asuser ${user} /bin/launchctl remove com.google.santagui
# and to clean out the log config, although it won't write after wiping the binary
/usr/bin/killall -HUP syslog
# delete artifacts on-disk
/bin/rm -rf /Applications/Santa.app
/bin/rm -rf /Library/Extensions/santa-driver.kext
/bin/rm -f /Library/LaunchAgents/com.google.santagui.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santad.plist
/bin/rm -f /private/etc/asl/com.google.santa.asl.conf
/bin/rm -f /usr/local/santactl # just a symlink
#uncomment to remove the config file and all databases, log files
#/bin/rm -rf /var/db/santa
#/bin/rm -f /var/log/santa*
exit 0