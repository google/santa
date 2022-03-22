---
parent: Details
---

# Logs

Separately from the [events](events.md) a sync server may receive in (close to)
real-time, with metadata that is helpful for maintaining rules, Santa logs to
`/var/db/santa/santa.log` by default (configurable with the [EventLogPath](../deployment/configuration.md)
key). All detected executions and disk mount operations are logged there.
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

For information more specific to Santa's health and operation, logs are also
present in ULS. Using the `show` command you can view Santa-specific logs in
flight, including messages related to the system extension:

```sh
/usr/bin/log show --info --debug --predicate 'senderImagePath CONTAINS[c] "santa"'
```
