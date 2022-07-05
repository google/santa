---
title: Home
nav_order: 1
---

# Welcome

Santa is a binary authorization system for macOS. It consists of a system extension that monitors for executions, a daemon that makes execution decisions based on the contents of a local database, a GUI agent that notifies the user in case of a block decision, and a command-line utility for managing the system and synchronizing the database with a server.

It is named Santa because it keeps track of binaries that are naughty or nice.

Here you'll find documentation for [understanding](introduction/index.md) how Santa works, [deploying Santa](deployment/index.md), and how to [contribute](development/contributing.md) to the project. 

## Features 

* [**Multiple modes:**](concepts/mode.md) In the default `MONITOR` mode, all binaries except those marked as blocked will be allowed to run, whilst being logged and recorded in the events database. In `LOCKDOWN` mode, only listed binaries are allowed to run.
* [**Event logging:**](concepts/events.md) When the kext is loaded, all binary launches are logged. When in either mode, all unknown or denied binaries are stored in the database to enable later aggregation.
* [**Certificate-based rules, with override levels:**](concepts/rules.md) Instead of relying on a binary's hash (or 'fingerprint'), executables can be allowed/blocked by their signing certificate. You can therefore allow/block all binaries by a given publisher that were signed with that cert across version updates. A binary can only be allowed by its certificate if its signature validates correctly but a rule for a binary's fingerprint will override a decision for a certificate; i.e. you can allowlist a certificate while blocking a binary signed with that certificate, or vice-versa.
* **Path-based rules (via NSRegularExpression/ICU):** This allows a similar feature to that found in Managed Client (the precursor to configuration profiles, which used the same implementation mechanism), Application Launch Restrictions via the mcxalr binary. This implementation carries the added benefit of being configurable via regex, and not relying on LaunchServices. As detailed in the wiki, when evaluating rules this holds the lowest precedence.
* [**Failsafe cert rules:**](concepts/rules.md#built-in-rules) You cannot put in a deny rule that would block the certificate used to sign launchd, a.k.a. pid 1, and therefore all components used in macOS. The binaries in every OS update (and in some cases entire new versions) are therefore automatically allowed. This does not affect binaries from Apple's App Store, which use various certs that change regularly for common apps. Likewise, you cannot block Santa itself, and Santa uses a distinct separate cert than other Google apps.
* [**Userland components validate each other:**](binaries/index.md) Each of the userland components (the daemon, the GUI agent, and the command-line utility) communicate with each other using XPC and check that their signing certificates are identical before any communication is accepted.
* **Caching:** Allowed binaries are cached so the processing required to make a request is only done if the binary isn't already cached.

## Documentation overview

### Introduction

The following pages give an overview of how Santa accomplishes binary authorization at the enterprise scale.

* [Binary Authorization](introduction/binary-authorization-overview.md): How Santa makes allow or deny decisions for any `execve()` taking place.
* [Syncing](introduction/syncing-overview.md): How configuration and rules are applied from a sync server.

### Deployment

* [Configuration](deployment/configuration.md): The local and sync server configuration options, along with example needed mobileconfig files.
* [Troubleshooting](deployment/troubleshooting.md): While there are numerous pages with details on Santa, admins may appreciate a central place to branch off from with common practical issues.

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

* [santad](details/santad.md): A userland root daemon that makes decisions.
* [santactl](details/santactl.md): A userland anonymous daemon that communicates with a sync server for configurations and policies. santactl can also be used by a user to manually configure Santa when using the local configuration.
* [santa-gui](details/santa-gui.md): A userland GUI daemon that displays notifications when an `execve()` is blocked.
* [santabs](details/santabs.md): A userland root daemon that finds Mach-O binaries within a bundle and creates events for them.

### Development

* [Building Santa](development/building.md): How to build and load Santa for testing on a development machine.
* [Contributing](development/contributing.md): How to contribute a bug fix or new feature to Santa.