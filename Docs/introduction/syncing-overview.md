# Syncing Overview

#### Background

Santa can be run and configured without a sync-server. Doing so will enable an admin to configure rules with the `santactl rule` command. Using a sync-server will enable an admin to configures rules and multiple other settings from the sync-server itself. Santa was designed from the start with a sync-server in mind. This allows an admin to easily configure and sync rules across a fleet of macOS systems. This document explains the syncing process.

#### Flow

This is a high level overview of the syncing process end to end. For a more a more detailed account of each part, see the respective documents. The santaclt binary can be run in one of two modes, daemon and non-daemon. The non-daemon mode does one full sync and exits. This is the typical way a user will interact with Santa, mainly to force a sync. The daemon mode is used by santad to schedule regular syncs, listen for instant notifications and uploading of events.

0. When the santad process starts up one of the first things it does is to look for a SyncBaseURL key/value in the config. If one exists it will `fork()` and `exec()` `santactl sync —-daemon`. Before the forked process runs all privileged are dropped. All privileged actions are then restricted to the XPC interface made available to santactl by santad. Since this santactl process is running as a daemon it too exports an XPC interface so santad can interact with the process efficiently and securely. To ensure syncing reliability santad will restart the santactl daemon if it is killed or crashes.
1. The santactl daemon process now schedules a full sync for 15 sec from now. The 15 sec is used to let santad settle before santactl potentially sending lot of rules to process.
2. The full sync starts. There are a number of stages to a full sync.
   1. preflight: The sync-server can set various settings for Santa.
   2. logupload (optional): The sync-server can request that the Santa logs be uploaded to an endpoint.
   3. eventupload (optional): If Santa has generated events it will upload them to the sync-server.
   4. ruledownload: Download rules from the sync-server.
   5. postflight: Updates timestamps for successful syncs.
3. After the full sync completes a new full sync will be scheduled, by default this will be 10min. However there are a few ways to manipulate this.
   1. The sync-server can send down a configuration in the preflight to override the 10min interval. It can be anything greater than 10min.
   2. Firebase Cloud Messaging (FCM) can be used. The sync-server can send down a configuration in the preflight to have the santactl daemon to start listening for FCM messages. If a connection to FCM is made, the full sync interval drops to a default of 4 hours. This can be further configured by a preflight configuration. The FCM connection allows the sync-sever to talk directly with Santa. This way we can reduce polling the sync-server dramatically. More details are available in the [syncing](../details/syncing.md) document.
4. Full syncs will continue to take place at their configured interval. If configured FCM messages will continue to be digested and acted upon.

#### santactl XPC interface

When running as a daemon the santactl process makes available an XPC interface for use by santad. This allows santad to send blocked binary or bundle events directly to santactl for immediate upload to the sync-server. Doing so makes for a smoother user experience. The binary that was blocked on macOS is immediately available for viewing or handling on the sync-server.

