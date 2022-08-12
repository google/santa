---
title: Getting Started
parent: Deployment
nav_order: 1
---

# Getting Started

This page shows you the process to get started with your deployment of Santa.

**Note:** You can combine each of the profiles listed in the following steps into a single profile containing the different payloads: configuration, TCC, system extension, and notifications.

1. (Optional) Set up a [sync server](../introduction/syncing-overview.md). For a list of open-source sync servers, see [Sync Servers](sync-servers.md). Without a sync server, [`santactl`](../binaries/santactl.md) can configure rules locally.

1. Create and install your Santa configuration profile to customize your deployment of Santa. See [Configuration](configuration.md) for a reference list of the available options and an [example profile](https://github.com/google/santa/blob/main/docs/deployment/com.google.santa.example.mobileconfig).

1. Install the TCC and system extension configuration profiles:

    - The TCC profile provides Santa the access it requires to read files anywhere on disk. See an [example TCC profile](https://github.com/google/santa/blob/main/docs/deployment/tcc.configuration-profile-policy.santa.example.mobileconfig).
    - The system extension profile allows Santa to run without approval from the user. See an [example system extension profile](https://github.com/google/santa/blob/main/docs/deployment/system-extension-policy.santa.example.mobileconfig).

1. (Optional) Customize and install the notification settings profile. This allows you to set up notifications to alert when Santa is switching [modes](../concepts/mode.md). See an [example notification settings profile](https://github.com/google/santa/blob/main/docs/deployment/notificationsettings.santa.example.mobileconfig).

    The notifications modified through this profile are different to the main Santa GUI pop-ups. To configure the [Santa GUI](../binaries/santa-gui.md) notifications, use the [configuration profile](configuration.md) (in step 2).

1. Install the latest Santa package from [GitHub](https://github.com/google/santa/releases) (where you can also find release notes). The package is distributed as a `PKG` wrapped inside a `DMG`, both of which are properly signed and can be validated.
