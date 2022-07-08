---
title: Home
nav_order: 1
---

# Welcome to the Santa documentation

Santa is a binary authorization system for macOS. It consists of a system extension that monitors for executions using a set of rules stored in a local database, a GUI agent that notifies the user in case of a block decision, a `santasyncservice` binary responsible for syncing the server and database, and a command-line utility for managing the system.

It is named Santa because it keeps track of binaries that are naughty or nice.

## Features 

* [**Multiple modes:**](concepts/mode.md) In the default `MONITOR` mode, all binaries except those marked as blocked will be allowed to run, whilst being logged and recorded in the events database. In `LOCKDOWN` mode, only listed binaries are allowed to run.
* [**Event logging:**](concepts/events.md) All binary launches are logged. When in either mode, all unknown or denied binaries are stored in the database to enable later aggregation.
* [**Certificate-based rules, with override levels:**](concepts/rules.md) Instead of relying on a binary's hash (or 'fingerprint'), executables can be allowed/blocked by their signing certificate. You can therefore allow/block all binaries by a given publisher that were signed with that cert across version updates. A binary can only be allowed by its certificate if its signature validates correctly but a rule for a binary's fingerprint will override a decision for a certificate; i.e. you can allowlist a certificate while blocking a binary signed with that certificate, or vice-versa.
* **Path-based rules (via NSRegularExpression/ICU):** Binaries can be allowed/blocked based on the path they are launched from by matching against a configurable regex.
* [**Failsafe cert rules:**](concepts/rules.md#built-in-rules) You cannot put in a deny rule that would block the certificate used to sign launchd, a.k.a. pid 1, and therefore all components used in macOS. The binaries in every OS update (and in some cases entire new versions) are therefore automatically allowed. This does not affect binaries from Apple's App Store, which use various certs that change regularly for common apps. Likewise, you cannot block Santa itself.
* [**Components validate each other:**](binaries/index.md) Each of the components (the daemon, the GUI agent, and the command-line utility) communicate with each other using XPC and check that their signing certificates are identical before any communication is accepted.
* **Caching:** Allowed binaries are cached so the processing required to make a request is only done if the binary isn't already cached.

## Documentation overview

### Introduction

The following pages give an overview of how Santa accomplishes authorization at enterprise scale.

* [Binary Authorization](introduction/binary-authorization-overview.md): How Santa makes allow or deny decisions for any execution taking place.
* [Syncing](introduction/syncing-overview.md): How configuration and rules are applied from a sync server.

### Deployment

* [Configuration](deployment/configuration.md): The local and sync server configuration options, along with example needed mobileconfig files.
* [Troubleshooting](deployment/troubleshooting.md): How to troubleshoot issues with your Santa deployment.

### Concepts

Additional documentation on the concepts that support the operation of the main components:

* [mode](details/mode.md): An operating mode, either Monitor or Lockdown.
* [events](details/events.md): Represents an `execve()` that was blocked, or would have been blocked, depending on the mode.
* [rules](details/rules.md): Represents allow or deny decisions for a given `execve()`. Can either be a binary's SHA-256 hash or a leaf code-signing certificate's SHA-256 hash.
* [scopes](details/scopes.md): The level at which an `execve()` was allowed or denied from taking place.
* [ipc](details/ipc.md): How all the components of Santa communicate.
  duction/syncing-overview.
* [logs](details/logs.md): What and where Santa logs.

### Binaries

There are five main components that make up Santa, see the following pages to understand their functionality:

* [santad](details/santad.md): A root daemon that makes decisions.
* [santactl](details/santactl.md): A command-line utility for inspecting the state and managing local configuration of Santa.
* [santa-gui](details/santa-gui.md): A GUI daemon that displays notifications when an execution is blocked.
* [santabs](details/santabs.md): A root daemon that finds binaries within a bundle to allow for easier rule-creation of bundled applications.

### Development

* [Building Santa](development/building.md): How to build and load Santa for testing on a development machine.
* [Contributing](development/contributing.md): How to contribute a bug fix or new feature to Santa.