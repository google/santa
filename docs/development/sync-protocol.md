---
title: Sync Protocol
parent: Development
---


# Summary

This document describes the protocol between Santa and the sync server, also known as the sync protocol. Implementors should be able to use this to create their own sync servers.

# Background

Santa can be run and configured with a sync server. This allows an admin to
easily configure and sync rules across a fleet of macOS systems.  In addition to
distributing rules, using a sync server enables an admin to override some local
configuration options e.g. `LOCKDOWN` mode on both a fleet-wide and
per-host basis.

# Protocol Overview

The sync protocol is an HTTP/JSON based protocol. As such it is
assumed that both the server and client add `Content-Type` headers are set to
`application/json`.

The sync protocol is client initiated and consists of 4 request-response
transactions called stages, `preflight`, `eventupload`, `ruledownload`, and `postflight`.
A sync may consist of all 4 stages, just the `eventupload` stage or just the `ruledownload` stage.

| Stage | What it Does |
|---|---|
| **Preflight** | Report current Santa settings and machine attributes to sync server & retrieve configuration settings |
| **Event Upload** | Report new blockable events to the sync server |
| **Rule Download** | Retrieves new rules |
| **Postflight** | Reports stats |

If the server returns an HTTP status other than `200` for any stage than the sync stops and the next stage is not performed.

At a high level this looks like the following sequence:

```mermaid
sequenceDiagram
   client ->> server: POST /preflight/<machine_id>
   server -->> client: preflight response (200)
   loop until all events are uploaded
   client ->> server: POST /eventupload/<machine_id>
   server -->> client: eventupload response (200)
   end
   loop until all rules are downloaded
   client ->> server: POST /ruledownload/<machine_id>
   server --> client: ruledownload response (200)
   end
   client ->> server: POST /postflight/<machine_id>
   server -->> client: postflight response (200)
```

Where `<machine_id>` is a unique string identifier for the client. By default
Santa uses the hardware UUID. It may also be set using the [MachineID, MachineIDPlist, and MachineIDKey options](../deployment/configuration.md) in the
configuration.

# Authentication

The protocol expects the client to authenticate the server via SSL/TLS. Additionally, a sync server may support client certificates and use mutual TLS.

# Stages

All URLs are of the form `/<stage_name>/<machine_id>`, e.g. the preflight URL is `/preflight/<machine_id>`.

## Preflight

The preflight stage is used by the client to report host information to the sync
server and to retrieve a limited set of configuration settings from the server.
These configuration options override the initial values set from the application
configuration profile.

This follows the following transaction:

```mermaid
sequenceDiagram
   client ->> server: POST /preflight/<machine_id>
   server -->> client: preflight response
```

### `preflight` Request
The request consists of the following JSON keys:

| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| serial_num    | YES | string | The macOS serial number from IOKit `kIOPlatformSerialNumberKey` |  "XXXZ30URLVDQ" |
| hostname      | YES | string | The FQDN hostname of the client | markowsky.example.com |
| os_version    | YES | string | The OS version of the client from /System/Library/CoreServices/SystemVersion.plist | 12.4 |
| os_build      | YES | string | The OS build from /System/Library/CoreServices/SystemVersion.plist | "21F5048e" |
| model_identifier | NO | string | The model of the macOS system  | |
| santa_version | YES | string | 2022.3 |
| primary_user  | YES | string | The username | markowsky |
| binary_rule_count | NO | int | Number of binary allow / deny rules the client has at time of sync | 1000 |
| certificate_rule_count | NO | int | Number of certificate allow / deny rules the client has at time of sync | 3400 |
| compiler_rule_count | NO | int | Number of compiler rules the client has time of sync |
| transitive_rule_count | NO | int | Number of transitive rules the client has at the time of sync |
| teamid_rule_count | NO | int | Number of TeamID rules the client has at the time of sync | 24 |
| signingid_rule_count | NO | int | Number of SigningID rules the client has at the time of sync | 11 |
| cdhash_rule_count | NO | int | Number of CDHash rules the client has at the time of sync | 22 |
| client_mode | YES | string | The mode the client is operating in, either "LOCKDOWN" or "MONITOR" | LOCKDOWN |
| request_clean_sync | NO | bool | The client has requested a clean sync of its rules from the server | true |


#### Example preflight request JSON Payload:

```json
{
  "compiler_rule_count" : 14,
  "client_mode" : "MONITOR",
  "santa_version" : "2022.6",
  "serial_num" : "XXXZ30URLVDQ",
  "binary_rule_count" : 43676,
  "hostname" : "markowsky.example.com",
  "primary_user" : "markowsky",
  "certificate_rule_count" : 2364,
  "teamid_rule_count" : 0,
  "signingid_rule_count" : 12,
  "cdhash_rule_count" : 34,
  "os_build" : "21F5048e",
  "transitive_rule_count" : 0,
  "os_version" : "12.4",
  "model_identifier" : "MacBookPro15,1",
  "request_clean_sync": true
}
```

### `preflight` Response

If all of the data is well formed, the server responds with an HTTP status code
of 200 and provides a JSON response. While none of the preflight response keys
are required, if not set it will result in the listed action being taken by the
client.

The JSON object has the following keys:

| Key                         | If Not Set                                  | Type    | Meaning | Example Value                        |
| --------------------------- | ------------------------------------------- | ------- | ------- | ------------------------------------ |
| enable_bundles              | Use previous setting                        | boolean | Enable bundle scanning | true |
| enable_transitive_rules     | Use previous setting                        | boolean | Whether or not to enable transitive allowlisting | true |
| batch_size                  | Use a Santa-defined default value           | integer | Number of events to upload at a time | 128 |
| full_sync_interval          | Defaults to 600 seconds                     | uint32 | Number of seconds between full syncs. Note: Santa enforces a minimum value of 60. The default value will be used if a smaller value is provided. | 600 |
| client_mode                 | Use previous setting                        | string  | Operating mode to set for the client | either `MONITOR` or `LOCKDOWN` |
| allowed_path_regex          | Use previous setting                        | string  | Regular expression to allow a binary to execute from a path | "/Users/markowsk/foo/.\*" |
| blocked_path_regex          | Use previous setting                        | string  | Regular expression to block a binary from executing by path | "/tmp/" |
| block_usb_mount             | Use previous setting                        | boolean | Block USB mass storage devices | true |
| remount_usb_mode            | No attempt to mount with flags will be made | string  | Force USB mass storage devices to be remounted with the given permissions (see [configuration](../deployment/configuration.md)). Note that `block_usb_mount` field must also be set for Santa to use this field. | `noexec,rdonly` |
| sync_type                   | A `NORMAL` sync is assumed                  | string  | If set, the type of sync that the client should perform. Must be one of:<br />1.) `NORMAL` (or not set) The server intends only to send new rules. The client will not drop any existing rules.<br />2.) `CLEAN` Instructs the client to drop all non-transitive rules. The server intends to entirely sync all rules.<br />3.) `CLEAN_ALL` Instructs the client to drop all rules. The server intends to entirely sync all rules.<br />See [Clean Syncs](#clean-syncs) for more info. | `NORMAL`, `CLEAN` or `CLEAN_ALL` |
| override_file_access_action | Use previous setting                        | string  | Override file access config policy action. Must be:<br />1.) `DISABLE` to not log or block any rule violations.<br />2.) `AUDIT_ONLY` to only log violations, not block anything.<br />3.) `NONE` to not override the config | `DISABLE`, `AUDIT_ONLY`, or `NONE` |


#### Example Preflight Response Payload

```json
{
 "batch_size": 100,
 "client_mode": "MONITOR",
 "allowed_path_regex": null,
 "blocked_path_regex": null,
 "clean_sync": false,
 "bundles_enabled": true,
 "enable_transitive_rules": false
}
```

### Clean Syncs

Clean syncs will result in rules being deleted from the host before applying the newly synced rule set from the server. When the server indicates it is performing a clean sync, it means it intends to sync all current rules to the client.

The client maintains a "sync type state" that controls the type of sync it wants to perform (i.e. `NORMAL`, `CLEAN` or `CLEAN_ALL`). This is typically set by using `santactl sync`, `santactl sync --clean`, or `santactl sync --clean-all` respectively. Either clean sync type state being set will result in the `request_clean_sync` key being set to true in the [Preflight Request](#preflight-request).

There are three types of syncs the server can set: `NORMAL`, `CLEAN`, and `CLEAN_ALL`. The server indicates the type of sync it wants to perform by setting the `sync_type` key in the [Preflight Response](#preflight-response). When a sever performs a `NORMAL` sync, it only intends to send new rules to the client. When a server performs either a `CLEAN` or `CLEAN_ALL` sync, it intends to send all rules and the client should delete appropriate rules (non-transitive, or all). The server should try to honor the `request_clean_sync` key if set to true in the [Preflight Request](#preflight-request) by setting the `sync_type` to `CLEAN` (or possibly `CLEAN_ALL` if desired).

The rules for resolving the type of sync that will be performed are as follows:
1. If the server responds with a `sync_type` of `CLEAN`, a clean sync is performed (regardless of whether or not it was requested by the client), unless the client sync type state was `CLEAN_ALL`, in which case a `CLEAN_ALL` sync type is performed.
2. If the server responded that it is performing a `CLEAN_ALL` sync, a `CLEAN_ALL` is performed (regardless of whether or not it was requested by the client)
3. Otherwise, a normal sync is performed

A client that has a `CLEAN` or `CLEAN_ALL` sync type state set will continue to request a clean sync until it is satisfied by the server. If a client has requested a clean sync, but the server has not responded that it will perform a clean sync, then the client will not delete any rules before applying the new rules received from the server.

If the deprecated [Preflight Response](#preflight-response) key `clean_sync` is set, it is treated as if the `sync_type` key were set to `CLEAN`. This is a change in behavior to what was previously performed in that not all rules are dropped anymore, only non-transitive rules. Servers should stop using the `clean_sync` key and migrate to using the `sync_type` key.

## EventUpload

After the `preflight` stage has completed the client then initiates the
`eventupload` stage if it has any events to upload. If there aren't any events
this stage is skipped.

It consists of the following transaction, that may be repeated until all events are uploaded.

```mermaid
sequenceDiagram
   client ->> server: POST /eventupload/<machine_id>
   server -->> client: eventupload response
```

### `eventupload` Request

| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| events | YES | list of event objects | list of events to upload | see example payload |


#### Event Objects

:information_source: Events are explained in more depth in the [Events page](../concepts/events.md).

| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| file_sha256 | YES | string | SHA256 hash of the executable that was executed | "fc6679da622c3ff38933220b8e73c7322ecdc94b4570c50ecab0da311b292682" |
| file_path | YES | string | Absolute file path to the executable that was blocked | "/tmp/foo" |
| file_name | YES | string | Command portion of the path of the blocked executable | "foo" |
| executing_user | NO | string | Username that executed the binary | "markowsky" |
| execution_time | NO | float64 | Unix timestamp of when the execution occurred | 23344234232 |
| loggedin_users | NO | list of strings | List of usernames logged in according to utmp | ["markowsky"] |
| current_sessions | NO | list of strings | List of user sessions | ["markowsky@console", "markowsky@ttys000"] |
| decision | YES | string | The decision Santa made for this binary, BUNDLE_BINARY is used to preemptively report binaries in a bundle. **Must be one of the examples** | "ALLOW_BINARY", "ALLOW_CERTIFICATE", "ALLOW_SCOPE", "ALLOW_TEAMID", "ALLOW_SIGNINGID", "ALLOW_CDHASH" "ALLOW_UNKNOWN", "BLOCK_BINARY", "BLOCK_CERTIFICATE", "BLOCK_SCOPE", "BLOCK_TEAMID", "BLOCK_SIGNINGID", "BLOCK_CDHASH", "BLOCK_UNKNOWN", "BUNDLE_BINARY" |
| file_bundle_id | NO | string |  The executable's containing bundle's identifier as specified in the Info.plist | "com.apple.safari" |
| file_bundle_path | NO | string | The path that the bundle resids in | /Applications/Santa.app |
| file_bundle_executable_rel_path | NO | string | The relative path of the binary within the Bundle | "Contents/MacOS/AppName" |
| file_bundle_name | NO | string | The bundle's display name | "Google Chrome" |
| file_bundle_version | NO | string | The bundle version string | "9999.1.1" |
| file_bundle_version_string | NO | string | Bundle short version string | "2.3.4" |
| file_bundle_hash | NO | string | SHA256 hash of all executables in the bundle | "7466e3687f540bcb7792c6d14d5a186667dbe18a85021857b42effe9f0370805" |
| file_bundle_hash_millis | NO | uint32 | The time in milliseconds it took to find all of the binaries, hash and produce the bundle_hash | 1234775 |
| file_bundle_binary_count | NO | uint32 | The number of binaries in a bundle | 13 |
| pid | NO | int | Process id of the executable that was blocked | 1234 |
| ppid | NO | int | Parent process id of the executable that was blocked | 456 |
| parent_name | NO | Parent process short command name of the executable that was blocked | "bar" |
| quarantine_data_url | NO | string |  The actual URL of the quarantined item from the quarantine database that this binary was downloaded from | https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg |
| quarantine_referer_url | NO | string | Referring URL that lead to the binary being downloaded if known  | https://www.google.com/chrome/downloads/ |
| quarantine_timestamp | NO | float64 | Unix Timestamp of when the binary was downloaded or 0 if not quarantined | 0 |
| quarantine_agent_bundle_id | NO | string | The bundle ID of the software that quarantined the binary | "com.apple.Safari" |
| signing_chain | NO | list of signing chain objects | Certs used to code sign the executable | See next section |
| signing_id | NO | string | Signing ID of the binary that was executed | "EQHXZ8M8AV:com.google.Chrome" |
| team_id | NO | string | Team ID of the binary that was executed | "EQHXZ8M8AV" |
| cdhash | NO | string | CDHash of the binary that was executed | "dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a" |

#### Signing Chain Objects

| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| sha256 | YES | string | SHA256 thumbprint of the certificate used to sign | "7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258" |
| cn | YES | string | Common Name field of the certificate used to sign | "Apple Worldwide Developer Relations Certification Authority" |
| org | YES | string | Org field of the certificate used to sign | "Google LLC" |
| ou | YES | string | OU field of the certificate used to sign | "G3" |
| valid_from | YES | int | Unix timestamp of when the cert was issued |  1647447514 |
| valid_until | YES | int | Unix timestamp of when the cert expires |  1678983513 |


#### `eventupload` Request Example Payload

```json
{
  "events": [{
    "file_path": "\/Applications\/Santa.app\/Contents\/MacOS",
    "file_bundle_version": "9999.1.1",
    "parent_name": "launchd",
    "logged_in_users": [
      "markowsky"
    ],
    "quarantine_timestamp": 0,
    "signing_chain": [{
        "cn": "Apple Development: Google Development (EQHXZ8M8AV)",
        "valid_until": 1678983513,
        "org": "Google LLC",
        "valid_from": 1647447514,
        "ou": "EQHXZ8M8AV",
        "sha256": "7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258"
      },
      {
        "cn": "Apple Worldwide Developer Relations Certification Authority",
        "valid_until": 1897776000,
        "org": "Apple Inc.",
        "valid_from": 1582136027,
        "ou": "G3",
        "sha256": "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f"
      },
      {
        "cn": "Apple Root CA",
        "valid_until": 2054670036,
        "org": "Apple Inc.",
        "valid_from": 1146001236,
        "ou": "Apple Certification Authority",
        "sha256": "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
      }
    ],
    "file_bundle_name": "santasyncservice",
    "executing_user": "root",
    "ppid": 1,
    "file_bundle_path": "/Applications/Santa.app",
    "file_name": "santasyncservice",
    "execution_time": 1657764366.475035,
    "file_sha256": "8621d92262aef379d3cfe9e099f287be5b996a281995b5cc64932f7d62f3dc85",
    "decision": "ALLOW_BINARY",
    "file_bundle_id": "com.google.santa.syncservice",
    "file_bundle_version_string": "9999.1.1",
    "pid": 2595,
    "current_sessions": [
      "markowsky@console",
      "markowsky@ttys000",
      "markowsky@ttys001",
      "markowsky@ttys003"
    ],
    "team_id": "EQHXZ8M8AV",
    "signing_id": "EQHXZ8M8AV:com.google.santa",
    "cdhash": "dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a"
  }]
}
```

### `eventupload` Response

The server should reply with an HTTP 200 if the request was successfully received and processed.


| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| event_upload_bundle_binaries | NO | list of strings | An array of bundle hashes that the sync server needs to be uploaded | ["8621d92262aef379d3cfe9e099f287be5b996a281995b5cc64932f7d62f3dc85"] |

#### `eventupload` Response Example Payload


```json
{
   "event_upload_bundle_binaries": ["8621d92262aef379d3cfe9e099f287be5b996a281995b5cc64932f7d62f3dc85"]
}
```

## Rule Download

After events have been uploaded to the sync server, the `ruledownload` stage begins in a full sync.

Like the previous stages this is a simple HTTP request response cycle like so:

```mermaid
sequenceDiagram
   client ->> server: POST /ruledownload/<machine_id>
   server -->> client: ruledownload response
```

If either the client or server requested a clean sync in the `preflight` stage, the client is expected to purge its existing rules and download new rules from the sync server.

If a clean sync was not requested by either the client or the sync service, then the sync service should only send new rules seen since the last time the client synced.

Santa applies rules idempotently and is designed to receive rules multiple times without issue.

One caveat to be aware of is that when a clean sync is requested in the `preflight` stage, the client expects that at least one rule will be sent by the sync service in the `ruledownload` stage. If no rules are sent then the client is expected to keep its old set of rules prior to the client or server requesting a clean sync and the client will continue to request a clean sync on all subsequent syncs until a successful sync completes that includes at least one rule.

### `ruledownload` Request

 This stage is initiated via an HTTP POST request to the URL `/ruledownload/<machine_id>`

| Key | Required | Type | Meaning |
|---|---|---|---|
| cursor | NO | string | a field used by the sync server to indicate where the next batch of rules should start |


#### `ruledownload` Request Example Payload

On the first request the payload is an empty dictionary

```json
{}
```

In the `ruledownload` response a special field called `cursor` will exist if there are more rules to download from server. The value and form of this field is left to the sync server implementor. It is expected to be used to track where the next batch of rules should start.

On subsequent requests to the server the `cursor` field is sent with the value from the previous response e.g.

```json
{"cursor":"CpgBChcKCnVwZGF0ZWRfZHQSCQjh94a58uLlAhJ5ahVzfmdvb2dsZS5jb206YXBwbm90aHJyYAsSCUJsb2NrYWJsZSJAMTczOThkYWQzZDAxZGRmYzllMmEwYjBiMWQxYzQyMjY1OWM2ZjA3YmU1MmY3ZjQ1OTVmNDNlZjRhZWI5MGI4YQwLEgRSdWxlGICA8MvA0tIJDBgAIAA="}
```

### `ruledownload` Response

When a `ruledownload` request is received, the sync server responds with a JSON object
containing a list of rule objects and a cursor so the client can resume
downloading if the rules need to be downloaded in multiple batches.

| Key | Required | Type | Meaning |
|---|---|---|---|
| cursor | NO | string | Used to continue a rule download in a future request |
| rules | YES | list of Rule objects | List of rule objects (see next section). |

#### Rules Objects


| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| identifier | YES | string | The attribute of the binary the rule should match on e.g. the signing ID, team ID, or CDHash of a binary or sha256 hash value | "ff2a7daa4c25cbd5b057e4471c6a22aba7d154dadfb5cce139c37cf795f41c9c" |
| policy | YES | string | Identifies the action to perform in response to the rule matching (must be one of the examples) | "ALLOWLIST","ALLOWLIST_COMPILER", "BLOCKLIST", "REMOVE",  "SILENT_BLOCKLIST" |
| rule\_type | YES | string | Identifies the type of rule (must be one of the examples) | "BINARY", "CERTIFICATE", "SIGNINGID", "TEAMID", "CDHASH"  |
| custom\_msg | NO | string | A custom message to display when the rule matches | "Hello" |
| custom\_url | NO | string | A custom URL to use for the open button when the rule matches | http://example.com |
| creation\_time | NO | float64 | Time the rule was created | 1573543803.349378 |
| file\_bundle\_binary\_count | NO | integer | The number of binaries in a bundle | 13 |
| file\_bundle\_hash | NO | string | The SHA256 of all binaries in a bundle | "7466e3687f540bcb7792c6d14d5a186667dbe18a85021857b42effe9f0370805" |


#### Example `ruledownload` Response Payload

```json
{
  "rules": [{
    "identifier": "ff2a7daa4c25cbd5b057e4471c6a22aba7d154dadfb5cce139c37cf795f41c9c",
    "rule_type": "CERTIFICATE",
    "policy": "BLOCKLIST",
    "custom_msg": "",
    "creation_time": 1573543803.349378
  }, {
    "identifier": "233e741538e1cdf4835b3f2662e372cf0c2694b7e20b4e4663559c7fb0a9f234",
    "rule_type": "BINARY",
    "policy": "ALLOWLIST",
    "custom_msg": "",
    "creation_time": 1573572118.380034
  },
  {
    "identifier": "EQHXZ8M8AV",
    "rule_type": "TEAMID",
    "policy": "ALLOWLIST",
    "custom_msg": "Allow Software Google's Team ID",
    "creation_time": 1576623399.151607
  }],
  "cursor": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXzfmdvb2dsZS5jb206YXBwbm90aHJyYAsSCUJsb2NrYWJsZSJANGYyYTA2MjY1ZjRiODQ2M2Y2YjI0MmNiZTMwMTNkMGZhNjlkNDUxNmI4OTU3Y2I3ZDAxZDcyMTJkM2NhZmZiNAwLEgRSdWxlGICA8Kehk9MKDBgAIAA="
}
```

## Postflight

The postflight stage is used for the client to inform the sync server that it has successfully finished syncing. After sending the request, the client is expected to update its internal state applying any configuration changes sent by the sync server during the preflight step.

This stage uses an HTTP POST request to the url `/postflight/<machine_id>`

```mermaid
sequenceDiagram
   client ->> server: POST /postflight/<machine_id>
   server -->> client: postflight response
```

### `postflight` Request

The request consists of the following JSON keys:

| Key | Required | Type | Meaning | Example Value |
|---|---|---|---|---|
| rules_received    | YES | int | The number of rules the client received from all ruledownlaod requests. | 211 |
| rules_processed      | YES | int | The number of rules that were processed from all ruledownload requests. | 212 |

#### Example postflight request JSON Payload:

```json
{
  "rules_received" : 211,
  "rules_processed" : 212
}
```


### `postflight` Response

The server should reply with an HTTP 200 if the request was successfully received and processed. Any message body is ignored by the client.

<div id="mermaidjs-code" style="visibility: hidden">
<script src="https://unpkg.com/mermaid@9.1.3/dist/mermaid.min.js"></script>
<script>
   document.addEventListener("DOMContentLoaded", function(event) {
    mermaid.initialize({
      startOnLoad:true,
      theme: "forest",
    });
    window.mermaid.init(undefined, document.querySelectorAll('.language-mermaid'));
});
</script>
</div>
