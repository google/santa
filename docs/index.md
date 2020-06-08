# Welcome to the Santa Docs

Santa is a binary authorization system for macOS. Here you will find the
documentation for understanding how Santa works, how to deploy it and how to
contribute.

#### Introduction

The following documents give an overview of how Santa accomplishes binary
authorization at the enterprise scale.

- [Binary Authorization](introduction/binary-authorization.md): How Santa makes allow or deny decisions for any `execve()` taking place.
- [Syncing](introduction/syncing-overview.md): How configuration and rules are applied from a sync server.

#### Deployment

* [Configuration](deployment/configuration.md): The local and sync server configuration options.

#### Development

* [Building Santa](development/building.md): How to build and load Santa for testing on a development machine.
* [Contributing](../CONTRIBUTING.md): How to contribute a bug fix or new feature to Santa.

#### Details

For those who want even more details on how Santa works under the hood, this section is for you.

###### Binaries

There are five main components that make up Santa whose core functionality is described in snippets below. For additional detail on each component, visit their respective pages. These quick descriptions do not encompass all the jobs performed by each component, but do provide a quick look at the basic functionality utilized to achieve the goal of binary authorization.

* [santa-driver](details/santa-driver.md): A macOS kernel extension that participates in `execve()` decisions.
* [santad](details/santad.md): A user-land root daemon that makes decisions on behalf of santa-driver requests.
* [santactl](details/santactl.md): A user-land anonymous daemon that communicates with a sync server for configurations and policies. santactl can also be used by a user to manually configure Santa when using the local configuration.
* [santa-gui](details/santa-gui.md): A user-land GUI daemon that displays notifications when an `execve()` is blocked.
* [santabs](details/santabs.md): A user-land root daemon that finds Mach-O binaries within a bundle and creates events for them. 

###### Concepts

Additional documentation on the concepts that support the operation of the main components:

* [mode](details/mode.md): An operating mode, either Monitor or Lockdown.
* [events](details/events.md): Represents an `execve()` that was blocked, or would have been blocked, depending on the mode.
* [rules](details/rules.md): Represents allow or deny decisions for a given `execve()`. Can either be a binary's SHA-256 hash or a leaf code-signing certificate's SHA-256 hash.
* [scopes](details/scopes.md): The level at which an `execve()` was allowed or denied from taking place.
* [syncing](introduction/syncing-overview.md): How Santa communicates with a TLS server for configuration, rules and event uploading.
* [ipc](details/ipc.md): How all the components of Santa communicate.
  duction/syncing-overview.
* [logs](details/logs.md): What and where Santa logs.
