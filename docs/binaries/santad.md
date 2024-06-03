---
parent: Binaries
---

# santad  (com.google.santa.daemon)

**Note:** This documentation refers to the main Santa daemon as `santad`, but
this process will typically be seen on the system by its full name:
`com.google.santa.daemon`.

The `santad` process makes decisions
about binary executions, file access, and mounting USB mass storage devices. It
also handles brokering all of the XPC connections between the various components
of Santa.

## On Launch

When `santad` starts, it configures the following:

*   Initializes the rule and event databases.
*   Establishes connections to `Santa` (GUI) and `santasyncservice` daemon.
*   Processes the config file.

Next, if configured to do so, `santad` begins to unmount/remount any connected
USB mass storage devices that violate policy.

Finally, `santad` establishes its connections to the
[Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
(ES) framework which is used to authorize actions and collect telemetry. Once
successfully registered, appropriate event streams are subscribed to and
`santad` is able to begin making decisions.

## Event Streams

Multiple ES clients are created, each with their own area of responsibility and
unique set of event streams.

| Client                 | Responsibility |
| ---------------------- | -------------- |
| Authorizer             | Applying policy to new executions |
| Recorder               | Gathering telemetry, creating transitive rules |
| File Access Authorizer | Enforcing FAA policy by tracking all file access events |
| Device Manager         | Blocking USB mounts or enforcing mounts contain specified flags |
| Tamper Resistance      | Protecting Santa components from tampering |

## Logging

`santad` logs can be configured to target one of several different outputs:

| Log Type | Description |
| ------   | ----------- |
| syslog   | Emits events as a human-readable, key/value pair string to the [Apple ULS](https://developer.apple.com/documentation/os/logging?language=objc) |
| file     | Similar output to `syslog`, but logs are sent to a file instead of the ULS |
| protobuf | Emits events with a rich set of data defined by the [santa.proto](https://github.com/google/santa/blob/main/Source/common/santa.proto) schema |
| json     | Similar to `protobuf`, but the output is converted to JSON (Note: This is not a performant option and should only be used in targeted situations or when logging is expected to be minimal) |
| null     | Disables logging |

## A note on performance

On an idling machine, `santad` and the other components of Santa consume
virtually no CPU and a minimal amount of memory (5-50MB). When lots of processes
execute at the same time, the CPU and memory usage can spike. All of the
execution authorizations are made on high priority threads to ensure decisions
are made as soon as possible. A watchdog thread will log warnings when there is
sustained CPU and memory usage detected.
