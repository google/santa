---
parent: Binaries
---

# santametricservice

The `santametricservice` is responsible for managing various counters and gauges
used by the Santa development team for monitoring important aspects of Santa
such as: CPU/memory usage, event counters, and event processing timers. Metrics are also often added for new and experimental features to help
ensure proper functionality.

Periodically, the state of all metrics are collected, converted to the
configured format and exported to the configured server.

**IMPORTANT:** Collected metrics are ***not*** sent back to Google. Metrics are
sent to whatever server is configured, which is nothing by default.

**NOTE:** At Google,
[Monarch](https://research.google/pubs/monarch-googles-planet-scale-in-memory-time-series-database/)
is used for its metrics system but this has limited value for other deployments.
See [Known Limitations](https://santa.dev/known-limitations) for more
information.
