# Logs

Santa currently logs to `/var/db/santa/santa.log` by default. All executions and
disk mounts are logged here. File operations can also be configured to be
logged. See the `FileChangesRegex` key in the
[configuration.md](../deployment/configuration.md) document.

To view the logs:

```sh
tail -F /var/db/santa/santa.log
```

The `-F` will continue watching the path even when the current file fills up and
rolls over.

##### macOS Unified Logging System (ULS)

Currently all of the most recent releases of Santa are built with the macOS
10.11 SDK. This allows Santa to continue to log to Apple System Logger (ASL)
instead of ULS. However, on macOS 10.12+ all of the Kernel logs are sent to ULS.
See the KEXT Logging section below for more details.

If you are building Santa yourself and using the macOS 10.12+ SDKs, Santa's logs
will be sent to ULS.

Work is currently underway to bypass ASL and ULS altogether, allowing Santa to
continue logging to `/var/db/santa/santa.log`. This change will also allow us to
add alternative logging formats, like Protocol Buffer or JSON.

##### KEXT Logging

Streaming logs from the santa-driver KEXT does not work properly. Logs are
generated but they will likely be garbled or show inaccurate data.

Instead, `show` can be used to view the santa-driver KEXT logs:

```sh
/usr/bin/log show --info --debug --predicate 'senderImagePath == "/Library/Extensions/santa-driver.kext/Contents/MacOS/santa-driver"'
```
