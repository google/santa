/// Copyright 2015-2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"

@class SNTRule;

///
///  Singleton that provides an interface for managing configuration values on disk
///  @note This class is designed as a singleton but that is not strictly enforced.
///  @note All properties are KVO compliant.
///
@interface SNTConfigurator : NSObject

#pragma mark - Daemon Settings

///
///  The operating mode. Defaults to MONITOR.
///
@property(readonly, nonatomic) SNTClientMode clientMode;

///
///  Set the operating mode as received from a sync server.
///
- (void)setSyncServerClientMode:(SNTClientMode)newMode;

///
///  Enable Fail Close mode. Defaults to NO.
///  This controls Santa's behavior when a failure occurs, such as an
///  inability to read a file. By default, to prevent bugs or misconfiguration
///  from rendering a machine inoperable Santa will fail open and allow
///  execution. With this setting enabled, Santa will fail closed if the client
///  is in LOCKDOWN mode, offering a higher level of security but with a higher
///  potential for causing problems.
///
@property(readonly, nonatomic) BOOL failClosed;

///
///  A set of static rules that should always apply. These can be used as a
///  fallback set of rules for management tools that should always be allowed to
///  run even if a sync server does something unexpected. It can also be used
///  as the sole source of rules, distributed with an MDM.
///
///  The value of this key should be an array containing dictionaries. Each
///  dictionary should contain the same keys used for syncing, e.g:
///
///  <key>StaticRules</key>
///  <array>
///    <dict>
///      <key>identifier</key>
///      <string>binary sha256, certificate sha256, team ID</string>
///      <key>rule_type</key>
///      <string>BINARY</string>  (one of BINARY, CERTIFICATE or TEAMID)
///      <key>policy</key>
///      <string>BLOCKLIST</string>  (one of ALLOWLIST, ALLOWLIST_COMPILER, BLOCKLIST,
///                                   SILENT_BLOCKLIST)
///    </dict>
///  </array>
///
///  The return of this property is a dictionary where the keys are the
///  identifiers of each rule, with the SNTRule as a value
///
@property(readonly, nonatomic) NSDictionary<NSString *, SNTRule *> *staticRules;

///
///  The regex of allowed paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(readonly, nonatomic) NSRegularExpression *allowedPathRegex;

///
///  Set the regex of allowed paths as received from a sync server.
///
- (void)setSyncServerAllowedPathRegex:(NSRegularExpression *)re;

///
///  The regex of blocked paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(readonly, nonatomic) NSRegularExpression *blockedPathRegex;

///
///  Set the regex of blocked paths as received from a sync server.
///
- (void)setSyncServerBlockedPathRegex:(NSRegularExpression *)re;

///
///  The regex of paths to log file changes for. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotalL) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(readonly, nonatomic) NSRegularExpression *fileChangesRegex;

///
///  A list of ignore prefixes which are checked in-kernel.
///  This is more performant than FileChangesRegex when ignoring whole directory trees.
///
///  For example adding a prefix of "/private/tmp/" will turn off file change log generation
///  in-kernel for that entire tree. Since they are ignored by the kernel, they never reach santad
///  and are not seen by the fileChangesRegex. Note the trailing "/", without it any file or
///  directory starting with "/private/tmp" would be ignored.
///
///  By default "/." and "/dev/" are added.
///
///  Memory in the kernel is precious. A total of MAXPATHLEN (1024) nodes are allowed.
///  Using all 1024 nodes will result in santa-driver allocating ~2MB of wired memory.
///  An ASCII character uses 1 node. An UTF-8 encoded Unicode character uses 1-4 nodes.
///  Prefixes are added to the running config in-order, one by one. The prefix will be ignored if
///  (the running config's current size) + (the prefix's size) totals up to more than 1024 nodes.
///  The running config is stored in a prefix tree.
///  Prefixes that share prefixes are effectively de-duped; their shared node sized components only
///  take up 1 node. For example these 3 prefixes all have a common prefix of "/private/".
///  They will only take up 21 nodes instead of 39.
///
///  "/private/tmp/"
///  "/private/var/"
///  "/private/new/"
///
///                                                              -> [t] -> [m] -> [p] -> [/]
///
///  [/] -> [p] -> [r] -> [i] -> [v] -> [a] -> [t] -> [e] -> [/] -> [v] -> [a] -> [r] -> [/]
///
///                                                              -> [n] -> [e] -> [w] -> [/]
///
///  Prefixes with Unicode characters work similarly. Assuming a UTF-8 encoding these two prefixes
///  are actually the same for the first 3 nodes. They take up 7 nodes instead of 10.
///
///  "/🤘"
///  "/🖖"
///
///                          -> [0xa4] -> [0x98]
///
///  [/] -> [0xf0] -> [0x9f]
///
///                          -> [0x96] -> [0x96]
///
///  To disable file change logging completely add "/".
///  TODO(bur): Make this default if no FileChangesRegex is set.
///
///  Filters are only applied on santad startup.
///  TODO(bur): Support add / remove of filters while santad is running.
///
@property(readonly, nonatomic) NSArray *fileChangesPrefixFilters;

///
///  Enable __PAGEZERO protection, defaults to YES
///  If this flag is set to NO, 32-bit binaries that are missing
///  the __PAGEZERO segment will not be blocked.
///
@property(readonly, nonatomic) BOOL enablePageZeroProtection;

///
///  Enable bad signature protection, defaults to NO.
///  When enabled, a binary that is signed but has a bad signature (cert revoked, binary
///  tampered with, etc.) will be blocked regardless of client-mode unless a binary allowlist
///  rule exists.
///
@property(readonly, nonatomic) BOOL enableBadSignatureProtection;

///
///  Defines how event logs are stored. Options are:
///    SNTEventLogTypeSyslog "syslog": Sent to ASL or ULS (if built with the 10.12 SDK or later).
///    SNTEventLogTypeFilelog "file": Sent to a file on disk. Use eventLogPath to specify a path.
///    SNTEventLogTypeNull "null": Logs nothing
///    SNTEventLogTypeProtobuf "protobuf": (BETA) Sent to a file on disk, using a maildir-like
///      format. Use spoolDirectory to specify a path. Use spoolDirectoryFileSizeThresholdKB,
///      spoolDirectorySizeThresholdMB and spoolDirectoryEventMaxFlushTimeSec to configure
///      additional settings.
///    Defaults to SNTEventLogTypeFilelog.
///    For mobileconfigs use EventLogType as the key and syslog or filelog strings as the value.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) SNTEventLogType eventLogType;

///
/// Returns the raw value of the EventLogType configuration key instead of being
/// converted to the SNTEventLogType enum. If the key is not set, the default log
/// type is returned.
///
@property(readonly, nonatomic) NSString *eventLogTypeRaw;

///
///  If eventLogType is set to Filelog, eventLogPath will provide the path to save logs.
///  Defaults to /var/db/santa/santa.log.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSString *eventLogPath;

///
///  If eventLogType is set to protobuf, spoolDirectory will provide the base path used for
///  saving logs using a maildir-like format.
///  Defaults to /var/db/santa/spool.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSString *spoolDirectory;

///
///  If eventLogType is set to protobuf, spoolDirectoryFileSizeThresholdKB sets the per-file size
///  limit for files saved in the spoolDirectory.
///  Defaults to 250.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSUInteger spoolDirectoryFileSizeThresholdKB;

///
///  If eventLogType is set to protobuf, spoolDirectorySizeThresholdMB sets the total size
///  limit for all files saved in the spoolDirectory.
///  Defaults to 100.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSUInteger spoolDirectorySizeThresholdMB;

///
///  If eventLogType is set to protobuf, spoolDirectoryEventMaxFlushTimeSec sets the maximum amount
///  of time an event will be stored in memory before being written to disk.
///  Defaults to 15.0.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) float spoolDirectoryEventMaxFlushTimeSec;

///
///  If set, contains the filesystem access policy configuration.
///
///  @note: The property fileAccessPolicyPlist will be ignored if
///         fileAccessPolicy is set.
///  @note: This property is KVO compliant.
///
@property(readonly, nonatomic) NSDictionary *fileAccessPolicy;

///
///  If set, contains the path to the filesystem access policy config plist.
///
///  @note: This property will be ignored if fileAccessPolicy is set.
///  @note: This property is KVO compliant.
///
@property(readonly, nonatomic) NSString *fileAccessPolicyPlist;

///
///  This is the message shown to the user when access to a file is blocked
///  by a binary due to some rule in the current File Access policy if that rule
///  doesn't provide a custom message. If this is not configured, a reasonable
///  default is provided.
///
///  @note: This property is KVO compliant.
///
@property(readonly, nonatomic) NSString *fileAccessBlockMessage;

///
///  If fileAccessPolicyPlist is set, fileAccessPolicyUpdateIntervalSec
///  sets the number of seconds between times that the configuration file is
///  re-read and policies reconstructed.
///  Defaults to 600 seconds (10 minutes)
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) uint32_t fileAccessPolicyUpdateIntervalSec;

///
/// Enabling this appends the Santa machine ID to the end of each log line. If nothing
/// has been overridden, this is the host's UUID.
/// Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableMachineIDDecoration;

#pragma mark - GUI Settings

///
///  When silent mode is enabled, Santa will never show notifications for
///  blocked processes.
///
///  This can be a very confusing experience for users, use with caution.
///
///  Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableSilentMode;

///
///  When silent TTY mode is enabled, Santa will not emit TTY notifications for
///  blocked processes.
///
///  Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableSilentTTYMode;

///
/// The text to display when opening Santa.app.
/// If unset, the default text will be displayed.
///
@property(readonly, nonatomic) NSString *aboutText;

///
///  The URL to open when the user clicks "More Info..." when opening Santa.app.
///  If unset, the button will not be displayed.
///
@property(readonly, nonatomic) NSURL *moreInfoURL;

///
///  When the user gets a block notification, a button can be displayed which will
///  take them to a web page with more information about that event.
///
///  This property contains a kind of format string to be turned into the URL to send them to.
///  The following sequences will be replaced in the final URL:
///
///  %file_sha%    -- SHA-256 of the file that was blocked.
///  %machine_id%  -- ID of the machine.
///  %username%    -- executing user.
///  %serial%      -- System's serial number.
///  %uuid%        -- System's UUID.
///  %hostname%    -- System's full hostname.
///
///  @note: This is not an NSURL because the format-string parsing is done elsewhere.
///
///  If this item isn't set, the Open Event button will not be displayed.
///
@property(readonly, nonatomic) NSString *eventDetailURL;

///
///  Related to the above property, this string represents the text to show on the button.
///
@property(readonly, nonatomic) NSString *eventDetailText;

///
///  In lockdown mode this is the message shown to the user when an unknown binary
///  is blocked. If this message is not configured, a reasonable default is provided.
///
@property(readonly, nonatomic) NSString *unknownBlockMessage;

///
///  This is the message shown to the user when a binary is blocked because of a rule,
///  if that rule doesn't provide a custom message. If this is not configured, a reasonable
///  default is provided.
///
@property(readonly, nonatomic) NSString *bannedBlockMessage;

///
/// This is the message shown to the user when a USB storage device's mount is denied
/// from the BlockUSB configuration setting. If not configured, a reasonable
/// default is provided.
///
@property(readonly, nonatomic) NSString *bannedUSBBlockMessage;

///
/// This is the message shown to the user when a USB storage device's mount is forcibly
/// remounted to a different set of permissions from the BlockUSB and RemountUSBMode
/// configuration settings. If not configured, a reasonable default is provided.
///
@property(readonly, nonatomic) NSString *remountUSBBlockMessage;

///
///  The notification text to display when the client goes into MONITOR mode.
///  Defaults to "Switching into Monitor mode"
///
@property(readonly, nonatomic) NSString *modeNotificationMonitor;

///
///  The notification text to display when the client goes into LOCKDOWN mode.
///  Defaults to "Switching into Lockdown mode"
///
@property(readonly, nonatomic) NSString *modeNotificationLockdown;

#pragma mark - Sync Settings

///
///  The base URL of the sync server.
///
@property(readonly, nonatomic) NSURL *syncBaseURL;

///
///  Proxy settings for syncing.
///  This dictionary is passed directly to NSURLSession. The allowed keys
///  are loosely documented at
///  https://developer.apple.com/documentation/cfnetwork/global_proxy_settings_constants.
///
@property(readonly, nonatomic) NSDictionary *syncProxyConfig;

///
///  Extra headers to include in all requests made during syncing.
///  Keys and values must all be strings, any other type will be silently ignored.
///  Some headers cannot be set through this key, including:
///
///    * Content-Encoding
///    * Content-Length
///    * Content-Type
///    * Connection
///    * Host
///    * Proxy-Authenticate
///    * Proxy-Authorization
///    * WWW-Authenticate
///
///  The header "Authorization" is also documented by Apple to be one that will
///  be ignored but this is not really the case, at least at present. If you
///  are able to use a different header for this that would be safest but if not
///  using Authorization /should/ be fine.
///
@property(readonly, nonatomic) NSDictionary *syncExtraHeaders;

///
///  The machine owner.
///
@property(readonly, nonatomic) NSString *machineOwner;

///
///  The last date of a successful full sync.
///
@property(nonatomic) NSDate *fullSyncLastSuccess;

///
///  The last date of a successful rule sync.
///
@property(nonatomic) NSDate *ruleSyncLastSuccess;

///
///  Type of sync required (e.g. normal, clean, etc.).
///
@property(nonatomic) SNTSyncType syncTypeRequired;

#pragma mark - USB Settings

///
/// USB Mount Blocking. Defaults to false.
///
@property(nonatomic) BOOL blockUSBMount;

///
/// Comma-separated `$ mount -o` arguments used for forced remounting of USB devices. Default
/// to fully allow/deny without remounting if unset.
///
@property(nonatomic) NSArray<NSString *> *remountUSBMode;

///
/// If set, defines the action that should be taken on existing USB mounts when
/// Santa starts up.
///
/// Supported values are:
///   * "Unmount": Unmount mass storage devices
///   * "ForceUnmount": Force unmount mass storage devices
///
///
/// Note: Existing mounts with mount flags that are a superset of RemountUSBMode
/// are unaffected and left mounted.
///
@property(readonly, nonatomic) SNTDeviceManagerStartupPreferences onStartUSBOptions;

///
/// If set, will override the action taken when a file access rule violation
/// occurs. This setting will apply across all rules in the file access policy.
///
/// Possible values are
///   * "AuditOnly": When a rule is violated, it will be logged, but the access
///     will not be blocked
///   * "Disable": No access will be logged or blocked.
///
/// If not set, no override will take place and the file acces spolicy will
/// apply as configured.
///
@property(readonly, nonatomic) SNTOverrideFileAccessAction overrideFileAccessAction;

///
///  Set the action that will override file access policy config action
///
- (void)setSyncServerOverrideFileAccessAction:(NSString *)action;

///
///  If set, this over-rides the default machine ID used for syncing.
///
@property(readonly, nonatomic) NSString *machineID;

///
///  If YES, enables bundle detection for blocked events. This property is not stored on disk.
///  Its value is set by a sync server that supports bundles. Defaults to NO.
///
@property BOOL enableBundles;

#pragma mark Transitive Allowlist Settings

///
///  If YES, binaries marked with SNTRuleStateAllowCompiler rules are allowed to transitively
///  allow any executables that they produce.  If NO, SNTRuleStateAllowCompiler rules are
///  interpreted as if they were simply SNTRuleStateAllow rules.  Defaults to NO.
///
@property BOOL enableTransitiveRules;

#pragma mark Server Auth Settings

///
///  If set, this is valid PEM containing one or more certificates to be used to evaluate the
///  server's SSL chain, overriding the list of trusted CAs distributed with the OS.
///
@property(readonly, nonatomic) NSData *syncServerAuthRootsData;

///
///  This property is the same as the above but is a file on disk containing the PEM data.
///
@property(readonly, nonatomic) NSString *syncServerAuthRootsFile;

#pragma mark Client Auth Settings

///
///  If set, this contains the location of a PKCS#12 certificate to be used for sync authentication.
///
@property(readonly, nonatomic) NSString *syncClientAuthCertificateFile;

///
///  Contains the password for the pkcs#12 certificate.
///
@property(readonly, nonatomic) NSString *syncClientAuthCertificatePassword;

///
///  If set, this is the Common Name of a certificate in the System keychain to be used for
///  sync authentication. The corresponding private key must also be in the keychain.
///
@property(readonly, nonatomic) NSString *syncClientAuthCertificateCn;

///
///  If set, this is the Issuer Name of a certificate in the System keychain to be used for
///  sync authentication. The corresponding private key must also be in the keychain.
///
@property(readonly, nonatomic) NSString *syncClientAuthCertificateIssuer;

///
///  If true, syncs will upload events when a clean sync is requested. Defaults to false.
///
@property(readonly, nonatomic) BOOL enableCleanSyncEventUpload;

///
///  If true, events will be uploaded for all executions, even those that are allowed.
///  Use with caution, this generates a lot of events. Defaults to false.
///
@property(nonatomic) BOOL enableAllEventUpload;

///
///  If true, events will *not* be uploaded for ALLOW_UNKNOWN events for clients in Monitor mode.
///
@property(nonatomic) BOOL disableUnknownEventUpload;

///
///  If true, forks and exits will be logged. Defaults to false.
///
@property(readonly, nonatomic) BOOL enableForkAndExitLogging;

///
///  If true, ignore actions from other endpoint security clients. Defaults to false. This only
///  applies when running as a sysx.
///
@property(readonly, nonatomic) BOOL ignoreOtherEndpointSecurityClients;

///
///  If true, debug logging will be enabled for all Santa components. Defaults to false.
///  Passing --debug as an executable argument will enable debug logging for that specific
///  component.
///
@property(readonly, nonatomic) BOOL enableDebugLogging;

///
///  If true, compressed requests from "santactl sync" will set "Content-Encoding" to "zlib"
///  instead of the new default "deflate". If syncing with Upvote deployed at commit 0b4477d
///  or below, set this option to true.
///  Defaults to false.
///
@property(readonly, nonatomic) BOOL enableBackwardsCompatibleContentEncoding;

///
/// If set, "santactl sync" will use the supplied "Content-Encoding", possible
/// settings include "gzip", "deflate", "none". If empty defaults to "deflate".
///
@property(readonly, nonatomic) SNTSyncContentEncoding syncClientContentEncoding;

///
///  Contains the FCM project name.
///
@property(readonly, nonatomic) NSString *fcmProject;

///
///  Contains the FCM project entity.
///
@property(readonly, nonatomic) NSString *fcmEntity;

///
///  Contains the FCM project API key.
///
@property(readonly, nonatomic) NSString *fcmAPIKey;

///
///  True if fcmProject, fcmEntity and fcmAPIKey are all set. Defaults to false.
///
@property(readonly, nonatomic) BOOL fcmEnabled;

///
/// True if metricsFormat and metricsURL are set. False otherwise.
///
@property(readonly, nonatomic) BOOL exportMetrics;

///
/// Format to export Metrics as.
///
@property(readonly, nonatomic) SNTMetricFormatType metricFormat;

///
/// URL describing where metrics are exported, defaults to nil.
///
@property(readonly, nonatomic) NSURL *metricURL;

///
/// Extra Metric Labels to add to the metrics payloads.
///
@property(readonly, nonatomic) NSDictionary *extraMetricLabels;

///
/// Duration in seconds of how often the metrics should be exported.
///
@property(readonly, nonatomic) NSUInteger metricExportInterval;

///
/// Duration in seconds for metrics export timeout. Defaults to 30;
///
@property(readonly, nonatomic) NSUInteger metricExportTimeout;

///
/// List of prefix strings for which individual entitlement keys with a matching
/// prefix should not be logged.
///
@property(readonly, nonatomic) NSArray<NSString *> *entitlementsPrefixFilter;

///
/// List of TeamIDs for which entitlements should not be logged. Use the string
/// "platform" to refer to platform binaries.
///
@property(readonly, nonatomic) NSArray<NSString *> *entitlementsTeamIDFilter;

///
///  Retrieve an initialized singleton configurator object using the default file path.
///
+ (instancetype)configurator;

///
///  Clear the sync server configuration from the effective configuration.
///
- (void)clearSyncState;

@end
