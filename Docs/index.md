# Welcome to the Santa Docs

Santa is a binary whitelisting/blacklisting system for macOS. Here you will find the documentation for understanding how Santa works, how to deploy it and how to contribute.

#### Introduction

The following documents give an overview on how Santa accomplishes binary whitelisting/blacklisting at the enterprise scale.

- [Binary Whitelisting](introduction/binary-whitelisting-overview.md): How Santa makes allow or deny decisions for any `exec()` taking place.
- [Syncing](introduction/syncing-overview.md): How configuration and whitelist/blacklist rules are applied from a sync-server.

#### Deployment

* [Configuration](deployment/configuration.md): The local and sync-server configuration options.

#### Development

* [Building Santa](development/building.md): How to build and load test builds of Santa on a development machine.
* Contributing: How to contribute a bug fix or new feature to Santa.

#### Details

For those who want even more details on how Santa works under the hood, this section is for you.

There are a four main components that make up Santa. There are documents explaining each piece in detail. Here is a quick one-liner on each component. These quick descriptions do not encompass all the jobs performed by each component, but do provide a quick look at the basic functionality utilized to achieve the goal of binary whitelisting/blacklisting.

* [santa-driver](details/santa-driver.md): A macOS kernel extension that participates in `exec()` decisions.
* [santad](details/santad.md): A user-land root daemon that makes decisions on behalf of santa-driver requests.
* [santactl](details/santactl.md): A user-land anonymous daemon that communicates with a sync-server for configurations and policies. santactl can also be used to by a user to manually configure Santa when not using a sync-server.
* [santa-gui](details/santa-gui.md): A user-land GUI daemon that displays notifications when an `exec()` is blocked.

There are also documents on concepts that support the workings of the main components.

* [config](details/config.md): The config is a plist that holds the config state of Santa on disk. It lives here: `/var/db/santa/config.plist`.
* [mode](details/mode.md): An operating mode, either Monitor or Lockdown.
* [events](details/events.md): Represents an `exec()` that was blocked, or would have been blocked, depending on the mode.
* [rules](details/rules.md): Represents allow or deny decisions for a given `exec()`. Can either be a binary's SHA-256 hash or a leaf code-signing certificate's SHA-256 hash.
* [scopes](details/scopes.md): The level at which an exec() was allowed or denied from taking place.
* [syncing](details/syncing.md): How Santa communicates with a TLS server for configuration, rules and event uploading.
* [ipc](details/ipc.md): How all the components of Santa communicate.
* [logs](details/logs.md): What and where Santa logs.
