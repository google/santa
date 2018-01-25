# Important

Santa v0.9.21 has moved to using an Apple [Configuration Profile](https://developer.apple.com/library/content/featuredarticles/iPhoneConfigurationProfileRef/Introduction/Introduction.html) to manage the local configuration. The old config file (`/var/db/santa/config.plist`) is no longer used.

# Configuration

Two configuration methods can be used to control Santa: a local configuration profile and a sync server controlled configuration. There are certain options that can only be controlled with a local configuration profile and others that can only be controlled with a sync server controlled configuration. Additionally, there are options that can be controlled by both.

## Local Configuration Profile

| Key                           | Value Type | Description                              |
| ----------------------------- | ---------- | ---------------------------------------- |
| ClientMode*                   | Integer    | 1 = MONITOR, 2 = LOCKDOWN, defaults to MONITOR |
| FileChangesRegex*             | String     | The regex of paths to log file changes. Regexes are specified in ICU format. |
| WhitelistRegex*               | String     | A regex to whitelist if the binary or certificate scopes did not allow execution.  Regexes are specified in ICU format. |
| BlacklistRegex*               | String     | A regex to blacklist if the binary or certificate scopes did not block an execution.  Regexes are specified in ICU format. |
| EnablePageZeroProtection      | Bool       | Enable `__PAGEZERO` protection, defaults to YES. If this flag is set to YES, 32-bit binaries that are missing the `__PAGEZERO` segment will be blocked even in MONITOR mode, **unless** the binary is whitelisted by an explicit rule. |
| MoreInfoURL                   | String     | The URL to open when the user clicks "More Info..." when opening Santa.app.  If unset, the button will not be displayed. |
| EventDetailURL                | String     | See the [EventDetailURL](#eventdetailurl) section below. |
| EventDetailText               | String     | Related to the above property, this string represents the text to show on the button. |
| UnknownBlockMessage           | String     | In Lockdown mode this is the message shown to the user when an unknown binary is blocked. If this message is not configured a reasonable default is provided. |
| BannedBlockMessage            | String     | This is the message shown to the user when a binary is blocked because of a rule if that rule doesn't provide a custom message. If this is not configured a reasonable  default is provided. |
| ModeNotificationMonitor       | String     | The notification text to display when the client goes into Monitor mode. Defaults to "Switching into Monitor mode". |
| ModeNotificationLockdown      | String     | The notification text to display when the client goes into Lockdown mode. Defaults to "Switching into Lockdown mode". |
| SyncBaseURL*                  | String     | The base URL of the sync server.         |
| ClientAuthCertificateFile     | String     | If set, this contains the location of a PKCS#12 certificate to be used for sync authentication. |
| ClientAuthCertificatePassword | String     | Contains the password for the PKCS#12 certificate. |
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

*overridable by the sync server: run `santactl status` to check the current running config

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

##### Example Configuration Profile

Here is an example of a configuration profile that could be set. It was generated with Tim Sutton's great [mcxToProfile](https://github.com/timsutton/mcxToProfile) tool. A copy is also available [here](com.google.santa.example.mobileconfig).

A few key points to when creating your configuration profile:

* `com.google.santa` needs to be the key inside `PayloadContent`
* The `PayloadScope` needs to be `System`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadContent</key>
			<dict>
				<key>com.google.santa</key>
				<dict>
					<key>Forced</key>
					<array>
						<dict>
							<key>mcx_preference_settings</key>
							<dict>
								<key>BannedBlockMessage</key>
								<string>This application has been banned</string>
								<key>ClientMode</key>
								<integer>1</integer>
								<key>EnablePageZeroProtection</key>
								<false/>
								<key>EventDetailText</key>
								<string>Open sync server</string>
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
						</dict>
					</array>
				</dict>
			</dict>
			<key>PayloadEnabled</key>
			<true/>
			<key>PayloadIdentifier</key>
			<string>0342c558-a101-4a08-a0b9-40cc00039ea5</string>
			<key>PayloadType</key>
			<string>com.apple.ManagedClient.preferences</string>
			<key>PayloadUUID</key>
			<string>0342c558-a101-4a08-a0b9-40cc00039ea5</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>com.google.santa</string>
	<key>PayloadDisplayName</key>
	<string>com.google.santa</string>
	<key>PayloadIdentifier</key>
	<string>com.google.santa</string>
	<key>PayloadOrganization</key>
	<string></string>
	<key>PayloadRemovalDisallowed</key>
	<true/>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>9020fb2d-cab3-420f-9268-acca4868bdd0</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>

```

Configuration profiles have a `.mobileconfig` file extension. There are many ways to install configuration profiles:

* Double click them in Finder
* Use the `/usr/bin/profiles` tool
* Use an MDM

## Sync server Provided Configuration

| Key                            | Value Type | Description                              |
| ------------------------------ | ---------- | ---------------------------------------- |
| client_mode                    | String     | MONITOR or LOCKDOWN, defaults to MONITOR. |
| clean_sync**                   | Bool       | If set to `True` Santa will clear all local rules and download a fresh copy from the sync-server. Defaults to `False`. |
| batch_size                     | Integer    | The number of rules to download or events to upload per request. Multiple requests will be made if there is more work than can fit in single request. Defaults to 50. |
| upload_logs_url**              | String     | If set, the endpoint to send Santa's current logs. No default. |
| whitelist_regex                | String     | Same as the "Local Configuration" WhitelistRegex. No default. |
| blacklist_regex                | String     | Same as the "Local Configuration" BlacklistRegex. No default. |
| fcm_token*                     | String     | The FCM token used by Santa to listen for FCM messages. Unique for every machine. No default. |
| fcm_full_sync_interval*        | Integer    | The full sync interval if a fcm_token is set. Defaults to  14400 secs (4 hours). |
| fcm_global_rule_sync_deadline* | Integer    | The max time to wait before performing a rule sync when a global rule sync FCM message is received. This allows syncing to be staggered for global events to avoid spikes in server load. Defaults to 600 secs (10 min). |
| bundles_enabled*               | Bool       | If set to `True` the bundle scanning feature is enabled. Defaults to `False`. |

*Held only in memory. Not persistent upon process restart.

**Performed once per preflight run (if set).
