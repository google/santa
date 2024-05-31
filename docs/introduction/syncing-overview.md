---
title: Syncing
parent: Intro
---

# Syncing Overview

## Background

Santa can be run and configured without a sync server. Doing so will enable an
admin to configure rules with the `santactl rule` command. Using a sync server
will enable an admin to configure rules and multiple other settings from the
sync server itself. Santa was designed from the start with a sync server in
mind. This allows an admin to easily configure and sync rules across a fleet of
macOS systems. This document explains the syncing process.

## Flow of a Full Sync

**NOTE:** Synchronization is now performed by its own daemon, the
`santasyncservice`.

This is a high level overview of the syncing process. For a more detailed
account of each part, see the documentation on the
[Sync Protocol](../development/sync-protocol.md).

Syncing is performed by the `santasyncservice` daemon. The daemon performs
routine full syncs and rule download only syncs, as well as listens for FCM push
notifications (when enabled). The daemon is also used by `santad` which can trigger event
uploads via an XPC call when a binary is blocked. The `santactl` command line
utility can also trigger full syncs via an XPC call with the `santactl sync`
command.

1.  When the `santad` process starts up, it establishes an XPC connection with
    the `santasyncservice` provided the `SyncBaseURL` configuration key is set.
1.  `santasyncservice` schedules a full sync to run 15 seconds in the future
    when the process starts up. This time is used to let `santad` settle before
    it would need to start receiving and updating rules.
1.  The full sync starts. This includes a number of stages:
    1.  `preflight`: The sync server can set various settings for Santa.
    1.  `eventupload` (optional): If Santa has generated events, it will upload
        them to the sync-server.
    1.  `ruledownload`: Download rules from the sync server.
    1.  `postflight`: Updates timestamps for successful syncs.
1.  After the full sync completes a new full sync will be scheduled, by default
    this will be 10 min. However there are a few ways to manipulate this:
    1.  The sync server can send down a configuration in the preflight to
        override the 10 min interval. It can be anything greater than 1 min.
    1.  Firebase Cloud Messaging (FCM) can be used*. The sync server can send
        down a configuration in the preflight to have the santactl daemon to
        start listening for FCM messages. If a connection to FCM is made, the
        full sync interval drops to a default of 4 hours. A preflight
        configuration can override this. The FCM connection allows the
        sync-server to talk directly with Santa. This way we can reduce polling
        the sync server dramatically.
1.  Full syncs will continue to take place at their configured interval. If
    configured FCM messages will continue to be digested and acted upon.

*The Firebase Cloud Messaging (FCM) based Push Notification system is only
available on the internal Google deployment of Santa at this time.

## Blocked Events

The `santad` daemon keeps an open XPC channel to the `santasyncservice`. This is
used by `santad` to send information about blocked binaries or bundle events as
they occur so that the information is immediately available for handling by the
sync server (e.g. making information about a blocked binary available for
viewing and potentially generating new rule sets).

## Manually Triggered Syncs

A full sync can be triggered at any time by using the `santactl sync` command.
This will message the `santasyncservice` via XPC to perform the required work.
Note that if a sync is already in progress, this command will block until that
sync is complete. Only normal user permissions are needed to trigger a sync
manually.
