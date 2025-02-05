---
title: Home
nav_order: 1
---

{: .important }
**As of 2025, Santa is no longer maintained by Google.**  We encourage existing
users to migrate to an actively maintained fork of Santa, such as
[https://github.com/northpolesec/santa](https://github.com/northpolesec/santa).

# Welcome to the Santa documentation

Santa is a binary and file access authorization system for macOS. It consists of a system extension that allows or denies attempted executions using a set of rules stored in a local database, a GUI agent that notifies the user in case of a block decision, a sync daemon responsible for syncing the database, and a server, and a command-line utility for managing the system.

It is named Santa because it keeps track of binaries that are naughty or nice.

The project and the latest release is available on [**GitHub**](https://github.com/google/santa).

## Features

* [**Multiple modes:**](concepts/mode.md) In the default `MONITOR` mode, all binaries except those marked as blocked will be allowed to run, while logged and recorded in the events database. In `LOCKDOWN` mode, only listed binaries are allowed to run.
* [**Event logging:**](concepts/events.md) All binary launches are logged. When in either mode, all unknown or denied binaries are stored in the database to enable later aggregation.
* [**Several supported rule types:**](concepts/rules.md) Executions can be allowed or denied by specifying rules based on several attributes. The supported rule types, in order of highest to lowest precedence are: CDHash, binary hash, Signing ID, certificate hash, or Team ID. Since multiple rules can apply to a given binary, Santa will apply the rule with the highest precedence (i.e. you could use a Team ID rule to allow all binaries from some organization, but also add a Signing ID rule to deny a specific binary). Rules based on code signature properties (Signing ID, certificate hash, and Team ID) only apply if a binary's signature validates correctly.
* **Path-based rules (via NSRegularExpression/ICU):** Binaries can be allowed/blocked based on the path they are launched from by matching against a configurable regex.
* [**Failsafe cert rules:**](concepts/rules.md#built-in-rules) You cannot put in a deny rule that would block the certificate used to sign launchd, a.k.a. pid 1, and therefore all components used in macOS. The binaries in every OS update (and in some cases entire new versions) are therefore automatically allowed. This does not affect binaries from Apple's App Store, which uses various certs that change regularly for common apps. Likewise, you cannot block Santa itself.
* [**Components validate each other:**](binaries/index.md) Each of the components (the daemons, the GUI agent, and the command-line utility) communicate with each other using XPC and check that their signing certificates are identical before any communication is accepted.
* **Caching:** Allowed binaries are cached, so the processing required to make a request is only done if the binary hasn't already been cached.

## Documentation overview

### Introduction

The following pages provide an overview of how Santa accomplishes authorization at an enterprise scale.

* [Binary Authorization](introduction/binary-authorization-overview.md): How Santa makes allow or deny decisions for any execution taking place.
* [Syncing](introduction/syncing-overview.md): How configuration and rules are applied from a sync server.

### Deployment

* [Getting Started](deployment/getting-started.md): A quick guide to setting up your deployment.
* [Configuration](deployment/configuration.md): The local and sync server configuration options, along with example needed mobileconfig files.
* [File Access Authorization](deployment/file-access-auth.md): Guide to enabling the feature and details about its configuration and operation.
* [Sync Servers](deployment/sync-servers.md): A list of open-source sync servers.
* [Troubleshooting](deployment/troubleshooting.md): How to troubleshoot issues with your Santa deployment.

### Concepts

Additional documentation on the concepts that support the operation of the main components:

* [mode](concepts/mode.md): An operating mode, either Monitor or Lockdown.
* [events](concepts/events.md): Represents an `execve()` that was blocked, or would have been blocked, depending on the mode.
* [rules](concepts/rules.md): Represents allow or deny decisions for a given `execve()`. Can either be a binary's SHA-256 hash or a leaf code-signing certificate's SHA-256 hash.
* [scopes](concepts/scopes.md): The level at which an `execve()` was allowed or denied from taking place.
* [ipc](concepts/ipc.md): How all the components of Santa communicate.
  duction/syncing-overview.
* [logs](concepts/logs.md): What and where Santa logs.

### Binaries

The following pages describe the main components that make up Santa:

* [santad](binaries/santad.md): A root daemon that makes decisions.
* [santactl](binaries/santactl.md): A command-line utility for inspecting the state and managing local configuration of Santa.
* [santa-gui](binaries/santa-gui.md): A GUI daemon that displays notifications when an execution is blocked.
* [santabundleservice](binaries/santabundleservice.md): A root daemon that finds binaries within a bundle to allow for easier rule-creation of bundled applications.

### Development

* [Building Santa](development/building.md): How to build and load Santa for testing on a development machine.
* [Contributing](development/contributing.md): How to contribute a bug fix or new feature to Santa.
