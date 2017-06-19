#### Local Configuration

| Key                           | Value Type | Description                              |
| ----------------------------- | ---------- | ---------------------------------------- |
| ClientMode*                   | Integer    | 1 for Monitor or 2 for Lockdown          |
| FileChangesRegex*             | String     | The regex of paths to log file changes. Regexes are specified in ICU format. |
| WhitelistRegex*               | String     | A regex to whitelist if the binary or certificate scopes did not allow execution.  Regexes are specified in ICU format. |
| BlacklistRegex*               | String     | A regex to blacklist if the binary or certificate scopes did not block an execution.  Regexes are specified in ICU format. |
| EnablePageZeroProtection      | Bool       | Enable `__PAGEZERO` protection, defaults to YES.  If this flag is set to NO, 32-bit binaries that are missing  the `__PAGEZERO` segment will not be blocked. |
| MoreInfoURL                   | String     | The URL to open when the user clicks "More Info..." when opening Santa.app.  If unset, the button will not be displayed. |
| EventDetailURL                | String     | See the Event URL Info section below.    |
| EventDetailText               | String     | Related to the above property, this string represents the text to show on the button. |
| UnknownBlockMessage           | String     | In lockdown mode this is the message shown to the user when an unknown binary is blocked. If this message is not configured, a reasonable default is provided. |
| BannedBlockMessage            | String     | This is the message shown to the user when a binary is blocked because of a rule, if that rule doesn't provide a custom message. If this is not configured, a reasonable  default is provided. |
| ModeNotificationMonitor       | String     | The notification text to display when the client goes into monitor mode. Defaults to "Switching into Monitor mode". |
| ModeNotificationLockdown      | String     | The notification text to display when the client goes into lockdown mode. Defaults to "Switching into Lockdown mode". |
| SyncBaseURL*                  | String     | The base URL of the sync server.         |
| ClientAuthCertificateFile     | String     | If set, this contains the location of a PKCS#12 certificate to be used for sync authentication. |
| ClientAuthCertificatePassword | String     | Contains the password for the pkcs#12 certificate. |
| ClientAuthCertificateCN       | String     | If set, this is the Common Name of a certificate in the System keychain to be used for sync authentication. The corresponding private key must also be in the keychain. |
| ClientAuthCertificateIssuerCN | String     | If set, this is the Issuer Name of a certificate in the System keychain to be used for sync authentication. The corresponding private key must also be in the keychain. |
| ServerAuthRootsData           | Data       | If set, this is valid PEM containing one or more certificates to be used to evaluate the server's SSL chain, overriding the list of trusted CAs distributed with the OS. |
| ServerAuthRootsFile           | String     | The same as the above but is a path to a file on disk containing the PEM data. |
| MachineOwner                  | String     | The machine owner.                       |
| MachineID                     | String     | The machine ID.                          |
| MachineOwnerPlist             | String     | The path to a plist that contains the MachineOwnerKey / value pair. |
| MachineOwnerKey               | String     | The key to use on MachineOwnerPlist.     |
| MachineIDPlist                | String     | The path to a plist that contains the MachineOwnerKey / value pair. |
| MachineIDKey                  | String     | The key to use on MachineIDPlist.        |

*protected keys: santad cannot be running to make a change

##### EventDetailURL

When the user gets a block notification, a button can be displayed which will take them to a web page with more information about that event.

This property contains a kind of format string to be turned into the URL to send them to. The following sequences will be replaced in the final URL:

| Key          | Description                              |
| ------------ | ---------------------------------------- |
| %file_sha%   | SHA-256 of the file that was blocked     |
| %machine_id% | ID of the machine                        |
| %username%   | The executing user                       |
| %bundle_id%  | Bundle ID of the binary, if applicable   |
| %bundle_ver% | Bundle version of the binary, if applicable |

For example: `https://sync-server-hostname/%machine_id%/%file_sha%`

##### Example Config

Here is an example of a configuration that could be set.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BannedBlockMessage</key>
	<string>This application has been banned</string>
	<key>ClientMode</key>
	<integer>1</integer>
	<key>EnablePageZeroProtection</key>
	<false/>
	<key>EventDetailText</key>
	<string>Open sync-server</string>
	<key>EventDetailURL</key>
	<string>https://sync-server-hostname/blockables/%file_sha%</string>
	<key>FileChangesRegex</key>
	<string>^/(?!(?:private/tmp|Library/(?:Caches|Managed Installs/Logs|(?:Managed )?Preferences))/)</string>
	<key>MachineIDKey</key>
	<string>MachineUUID</string>
	<key>MachineIDPlist</key>
	<string>/Library/Preferences/com.company.machine-mapping.plist</string>
	<key>MachineOwnerKey</key>
	<string>Owner</string>
	<key>MachineOwnerPlist</key>
	<string>/Library/Preferences/com.company.machine-mapping.plist</string>
	<key>ModeNotificationLockdown</key>
	<string>Entering Lockdown mode</string>
	<key>ModeNotificationMonitor</key>
	<string>Entering Monitor mode&lt;br/&gt;Please be careful!</string>
	<key>MoreInfoURL</key>
	<string>https://sync-server-hostname/moreinfo</string>
	<key>SyncBaseURL</key>
	<string>https://sync-server-hostname/api/santa/</string>
	<key>UnknownBlockMessage</key>
	<string>This application has been blocked from executing.</string>
</dict>
</plist>
```



#### Sync-server Provided Configuration

| Key                            | Value Type | Description                              |
| ------------------------------ | ---------- | ---------------------------------------- |
| client_mode                    | String     | MONITOR or  LOCKDOWN. Defaults to MONITOR. |
| clean_sync**                   | Bool       | If set to True Santa will clear all local rules and download a fresh copy from the sync-server. Defaults to False. |
| batch_size                     | Integer    | The number of rules to download or events to upload per request. Multiple requests will be made if there is more work than can fit in single request. Defaults to 50. |
| upload_logs_url**              | String     | If set, the endpoint to send Santa's current logs. No default. |
| whitelist_regex                | String     | Same as the "Local Configuration" WhitelistRegex. No default. |
| blacklist_regex                | String     | Same as the "Local Configuration" BlacklistRegex. No default. |
| fcm_token*                     | String     | The FCM token used by Santa to listen for FCM messages. Unique for every machine. No default. |
| fcm_full_sync_interval*        | Integer    | The full sync interval if a fcm_token is set. Defaults to  14400 secs (4 hours). |
| fcm_global_rule_sync_deadline* | Integer    | The max time to wait before performing a rule sync when a global rule sync FCM message is received. This allows syncing to be staggered for global events to avoid spikes in server load. Defaults to 600 secs (10 min). |
| bundles_enabled*               | Bool       | If set to True the bundle scanning feature is enabled. Defaults to False. |

*Held only in memory. Not persistent upon process restart.

**Performed once per preflight run (if set).