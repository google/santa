---
title: Configuration
parent: Deployment
---

# Configuration

Two configuration methods can be used to control Santa: a local configuration
profile and a sync server controlled configuration. There are certain options
that can only be controlled with a local configuration profile and others that
can only be controlled with a sync server controlled configuration.
Additionally, there are options that can be controlled by both, marked with a
single asterisk in the first table below.

Santa's local configuration is managed using Apple
[Configuration Profiles](https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf)(pdf link),
also known as mobileconfig files, which are in an Apple-specific XML format.


## Local Configuration Profile

| Key                           | Value Type | Description                              |
| ----------------------------- | ---------- | ---------------------------------------- |
| ClientMode\*                      | Integer    | 1 = MONITOR, 2 = LOCKDOWN, defaults to MONITOR |
| FailClosed                        | Bool       | If true and the ClientMode is LOCKDOWN: execution will be denied when there is an error reading or processing an executable file. |
| FileChangesRegex\*                | String     | The regex of paths to log file changes. Regexes are specified in ICU format. |
| AllowedPathRegex\*                | String     | A regex to allow if the binary or certificate scopes did not allow/block execution.  Regexes are specified in ICU format. |
| BlockedPathRegex\*                | String     | A regex to block if the binary or certificate scopes did not allow/block an execution.  Regexes are specified in ICU format. |
| EnableBadSignatureProtection      | Bool       | Enable bad signature protection, defaults to NO. If this flag is set to YES, binaries with a bad signing chain will be blocked even in MONITOR mode, **unless** the binary is allowed by an explicit rule. |
| EnablePageZeroProtection          | Bool       | Enable `__PAGEZERO` protection, defaults to YES. If this flag is set to YES, 32-bit binaries that are missing the `__PAGEZERO` segment will be blocked even in MONITOR mode, **unless** the binary is allowed by an explicit rule. |
| EnableSysxCache                   | Bool       | Enables a secondary cache that ensures better performance when multiple EndpointSecurity system extensions are installed. Defaults to YES in 2021.8, defaults to NO in earlier versions. |
| AboutText                         | String     | The text to display when the user opens Santa.app. If unset, the default text will be displayed. |
| MoreInfoURL                       | String     | The URL to open when the user clicks "More Info..." when opening Santa.app.  If unset, the button will not be displayed. |
| EventDetailURL                    | String     | See the [EventDetailURL](#eventdetailurl) section below. |
| EventDetailText                   | String     | Related to the above property, this string represents the text to show on the button. |
| UnknownBlockMessage               | String     | In Lockdown mode this is the message shown to the user when an unknown binary is blocked. If this message is not configured a reasonable default is provided. |
| BannedBlockMessage                | String     | This is the message shown to the user when a binary is blocked because of a rule if that rule doesn't provide a custom message. If this is not configured a reasonable  default is provided. |
| ModeNotificationMonitor           | String     | The notification text to display when the client goes into Monitor mode. Defaults to "Switching into Monitor mode". |
| ModeNotificationLockdown          | String     | The notification text to display when the client goes into Lockdown mode. Defaults to "Switching into Lockdown mode". |
| SyncBaseURL                       | String     | The base URL of the sync server.         |
| SyncProxyConfiguration            | Dictionary | The proxy configuration to use when syncing. See the [Apple Documentation](https://developer.apple.com/documentation/cfnetwork/global_proxy_settings_constants) for details on the keys that can be used in this dictionary. |
| ClientAuthCertificateFile         | String     | If set, this contains the location of a PKCS#12 certificate to be used for sync authentication. |
| ClientAuthCertificatePassword     | String     | Contains the password for the PKCS#12 certificate. |
| ClientAuthCertificateCN           | String     | If set, this is the Common Name of a certificate in the System keychain to be used for sync authentication. The corresponding private key must also be in the keychain. |
| ClientAuthCertificateIssuerCN     | String     | If set, this is the Issuer Name of a certificate in the System keychain to be used for sync authentication. The corresponding private key must also be in the keychain. |
| ServerAuthRootsData               | Data       | If set, this is valid PEM containing one or more certificates to be used for certificate pinning. To comply with [ATS](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW57) the certificate chain must also be trusted in the keychain. |
| ServerAuthRootsFile               | String     | The same as the above but is a path to a file on disk containing the PEM data. |
| MachineOwner                      | String     | The machine owner.                       |
| MachineID                         | String     | The machine ID.                          |
| MachineOwnerPlist                 | String     | The path to a plist that contains the MachineOwnerKey / value pair. |
| MachineOwnerKey                   | String     | The key to use on MachineOwnerPlist.     |
| MachineIDPlist                    | String     | The path to a plist that contains the MachineOwnerKey / value pair. |
| MachineIDKey                      | String     | The key to use on MachineIDPlist.        |
| EventLogType                      | String     | Defines how event logs are stored. Options are 1) syslog: Sent to ASL or ULS (if built with the 10.12 SDK or later). 2) filelog: Sent to a file on disk. Use EventLogPath to specify a path. 3) protobuf: Sent to file on disk using maildir format. Defaults to filelog.      |
| EventLogPath                      | String     | If EventLogType is set to filelog, EventLogPath will provide the path to save logs. Defaults to /var/db/santa/santa.log. If you change this value ensure you also update com.google.santa.newsyslog.conf with the new path.        |
| MailDirectory                     | String     | If EventLogType is set to protobuf, MailDirectory will provide the the base directory used to save files according to the maildir format. Defaults to /var/db/santa/mail. |
| MailDirectoryFileSizeThresholdKB  | Integer    | If EventLogType is set to protobuf, MailDirectoryFileSizeThresholdKB defines the per-file size limit for files stored in the mail directory. Events are buffered in memory until this threshold would be exceeded (or MailDirectoryEventMaxFlushTimeSec is exceeded). Defaults to 100. |
| MailDirectorySizeThresholdMB      | Integer    | If EventLogType is set to protobuf, MailDirectorySizeThresholdMB defines the total combined size limit of all files in the mail directory. Once the threshold is met, no more events will be saved. Defaults to 500. |
| MailDirectoryEventMaxFlushTimeSec | Integer    | If EventLogType is set to protobuf, MailDirectoryEventMaxFlushTimeSec defines the maximum amount of time events will stay buffered in memory before being flushed to disk, regardless of whether or not MailDirectoryFileSizeThresholdKB would be exceeded. Defaults to 5. |
| EnableMachineIDDecoration         | Bool       | If YES, this appends the MachineID to the end of each log line. Defaults to NO.       |
| MetricFormat                      | String     | Format to export metrics as, supported formats are "rawjson" for a single JSON blob and "monarchjson" for a format consumable by Google's Monarch tooling. Defaults to "". |
| MetricURL                         | String     | URL describing where monitoring metrics should be exported.  |
| MetricExportInterval              | Integer    | Number of seconds to wait between exporting metrics. Defaults to 30.  
| MetricExtraLabels                 | Dictionary | A map of key value pairs to add to all metric root labels. (e.g. a=b,c=d) defaults to @{}). If a previously set key (e.g. host_name is set to "" then the key is remove from the metric root labels. Alternatively if a value is set for an existing key then the new value will override the old. |


*overridable by the sync server: run `santactl status` to check the current
running config

##### EventDetailURL

When the user gets a block notification, a button can be displayed which will
take them to a web page with more information about that event.

This property contains a kind of format string to be turned into the URL to send
them to. The following sequences will be replaced in the final URL:

| Key          | Description                              |
| ------------ | ---------------------------------------- |
| %file_sha%   | SHA-256 of the file that was blocked     |
| %machine_id% | ID of the machine                        |
| %username%   | The executing user                       |
| %serial%     | System's serial number                   |
| %uuid%       | System's UUID                            |
| %hostname%   | System's full hostname                   |

For example: `https://sync-server-hostname/%machine_id%/%file_sha%`

##### Example Configuration Profile

Here is an example of a configuration profile that could be set. It was
generated with Tim Sutton's great
[mcxToProfile](https://github.com/timsutton/mcxToProfile) tool. A copy is also
available [here](com.google.santa.example.mobileconfig).

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

Configuration profiles have a `.mobileconfig` file extension. There are a couple
ways to install configuration profiles:

* Double click them in Finder
* Use an MDM, which is discussed further below

## Sync Server Provided Configuration

| Key                                 | Value Type | Description                              |
| ----------------------------------- | ---------- | ---------------------------------------- |
| client\_mode                        | String     | MONITOR or LOCKDOWN, defaults to MONITOR. |
| clean\_sync\*\*                     | Bool       | If set to `True` Santa will clear all local rules and download a fresh copy from the sync-server. Defaults to `False`. |
| batch\_size                         | Integer    | The number of rules to download or events to upload per request. Multiple requests will be made if there is more work than can fit in single request. Defaults to 50. |
| upload\_logs\_url\*\*               | String     | If set, the endpoint to send Santa's current logs. No default. |
| allowed\_path\_regex                | String     | Same as the "Local Configuration" AllowedPathRegex. No default. |
| blocked\_path\_regex                | String     | Same as the "Local Configuration" BlockedPathRegex. No default. |
| full\_sync\_interval\*              | Integer    | The max time to wait before performing a full sync with the server. Defaults to 600 secs (10 minutes) if not set. |
| fcm\_token\*                        | String     | The FCM token used by Santa to listen for FCM messages. Unique for every machine. No default. |
| fcm\_full\_sync\_interval\*         | Integer    | The full sync interval if a fcm\_token is set. Defaults to  14400 secs (4 hours). |
| fcm\_global\_rule\_sync\_deadline\* | Integer    | The max time to wait before performing a rule sync when a global rule sync FCM message is received. This allows syncing to be staggered for global events to avoid spikes in server load. Defaults to 600 secs (10 min). |
| enable\_bundles\*                   | Bool       | If set to `True` the bundle scanning feature is enabled. Defaults to `False`. |
| enable\_transitive\_rules           | Bool       | If set to `True` the transitive rule feature is enabled. Defaults to `False`. |
| block\_usb\_mass\_storage           | Bool       | If set to 'True' blocking USB Mass storage feature is enabled. Defaults to `False`. | 
| remount\_usb\_mode                  | Array      | Array of strings for arguments to pass to mount -o (any of "rdonly", "noexec", "nosuid", "nobrowse", "noowners", "nodev", "async", "-j"). when forcibly remounting devices. No default. |


*Held only in memory. Not persistent upon process restart.

**Performed once per preflight run (if set).


## MDM-Specific Client Configuration

As of macOS 10.14 Mojave, Apple introduced the requirement that various modes of
operation by executables on macOS had to be explicitly allowed and those
allowances could only be 'silently' applied with an MDM that had 'supervision'
status on a computer, either via automated device enrollment (also known as DEP)
or when opted in by the end user through a process referred to as User Approved
MDM.
This comes into play when a binary wants to have read access system-wide, for
example when an app is launched from a directory considered private to a user.
An example payload for this use case is provided [here](tcc.configuration-profile-policy.santa.example.mobileconfig)

This would be used alongside a payload allowing [notifications](notificationsettings.santa.example.mobileconfig) to be sent,
and for allowing the [system extension](https://github.com/google/santa/blob/main/docs/deployment/system-extension-policy.santa.example.mobileconfig) to be loaded without end user interaction.

Please note that for release package installers that included the kernel extension
as part of the payload (prior to 2021.8) the end user to be prompted to allow it
unless explicitly allowed with another MDM-delivered configuration profile to the
supervised system.
