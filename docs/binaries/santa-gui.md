---
parent: Binaries
---

# Santa GUI

The pupose of the Santa GUI is to display user GUI notifications. There are
several types of notifications it can display:

1.  [Blocked Executions](#blocked-executions)
1.  [Blocked File Access](#blocked-file-access)
1.  [Blocked USB Mounting](#blocked-usb-mounting)
1.  [User Notifications](#user-notifications)

## Blocked Executions

When Santa prevents a binary from executing, a dialog is presented to the user
containing information about what was denied (unless the rule was configured to
be "silent"). The message presented to the user as well as the text of the
"Open" button are configurable on both a global and per-rule basis.

![Example blocked execution dialog](blocked_execution.png)

## Blocked File Access

[File Access Authorization](https://santa.dev/deployment/file-access-auth.html)
allows admins to configure Santa to monitor filesystem paths for potentially
unwanted access and optionally deny the operation. The message presented to the
user as well as the text of the "Open" button are configurable on both a global
and per-rule basis.

![Example File Access Authorization block dialog blocking access to Chrome
Cookies](blocked_faa.png)

## Blocked USB Mounting

Santa can be configured to either prevent USB drives mounting, or force certain
options to be applied when mounting (such as mounting read-only).

![USB mount with forced flags](mount_forced_flags.png)

## User Notifications

Notifications when the client mode changes (e.g. from Monitor Mode to Lockdown
Mode) specific rules arrive (when using FCM for push notifications).

![Notification](push.png)
