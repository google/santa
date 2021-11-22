---
parent: Details
---

# Logs

Separate from the [events](events.md) a sync server may gather in (close to) real-time,
Santa logs to `/var/db/santa/santa.log` by default (configurable with the
[EventLogPath](../deployment/configuration.md) key). All detected executions and
disk mount operations are logged there.
File operations (when needed for functionality otherwise referred to as "file
integrity monitoring") can also be configured to be logged. See the
`FileChangesRegex` key in the [configuration.md](../deployment/configuration.md) document.

To view the logs:

```sh
tail -F /var/db/santa/santa.log
```

The `-F` will continue watching the path even when the current file fills up and
rolls over.

##### macOS Unified Logging System (ULS)

As Santa has been built with macOS 10.12+ SDKs for several releases, Santa's logs
are also sent to ULS.

Leveraging this capability, `show` can be used to view all santa-specific logs in
flight, including the system extension:

```sh
/usr/bin/log show --info --debug --predicate 'senderImagePath CONTAINS[c] "santa"'
```

For those still using the kernel extension, you would use a different command:

```sh
/usr/bin/log show --info --debug --predicate 'senderImagePath == "/Library/Extensions/santa-driver.kext/Contents/MacOS/santa-driver"'
````