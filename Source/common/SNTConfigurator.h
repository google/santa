/// Copyright 2015 Google Inc. All rights reserved.
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
///    SNTEventLogTypeSyslog: Sent to ASL or ULS (if built with the 10.12 SDK or later).
///    SNTEventLogTypeFilelog: Sent to a file on disk. Use eventLogPath to specify a path.
///    Defaults to SNTEventLogTypeFilelog.
///    For mobileconfigs use EventLogType as the key and syslog or filelog strings as the value.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) SNTEventLogType eventLogType;

///
///  If eventLogType is set to Filelog, eventLogPath will provide the path to save logs.
///  Defaults to /var/db/santa/santa.log.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSString *eventLogPath;

///
///  If eventLogType is set to protobuf, eventMailDirectory will provide the base path used for
///  saving logs.
///  Defaults to /var/db/santa/mail.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSString *eventMailDirectory;

///
/// Enabling this appends the Santa machine ID to the end of each log line. If nothing
/// has been overriden, this is the host's UUID.
/// Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableMachineIDDecoration;

///
///  Use the bundled SystemExtension on macOS 10.15+, defaults to YES.
///  Disable to continue using the bundled KEXT.
///  This is a one way switch, if this is ever true on macOS 10.15+ the KEXT will be deleted.
///  This gives admins control over the timing of switching to the SystemExtension. The intended use
///  case is to have an MDM deliver the requisite SystemExtension and TCC profiles before attempting
///  to load.
///
@property(readonly, nonatomic) BOOL enableSystemExtension;

///
///  Use an internal cache for decisions instead of relying on the caching
///  mechanism built-in to the EndpointSecurity framework. This may increase
///  performance, particularly when Santa is run alongside other system
///  extensions.
///  Has no effect if the system extension is not being used. Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableSysxCache;

#pragma mark - GUI Settings

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
///  If YES a clean sync is required.
///
@property(nonatomic) BOOL syncCleanRequired;

///
/// USB Mount Blocking. Defaults to false.
///
@property(nonatomic) BOOL blockUSBMount;

///
/// Comma-seperated `$ mount -o` arguments used for forced remounting of USB devices. Default
/// to fully allow/deny without remounting if unset.
///
@property(nonatomic) NSArray<NSString *> *remountUSBMode;

///
/// When `blockUSBMount` is set, this is the message shown to the user when a device is blocked
/// If this message is not configured, a reasonable default is provided.
///
@property(readonly, nonatomic) NSString *usbBlockMessage;

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
///  Retrieve an initialized singleton configurator object using the default file path.
///
+ (instancetype)configurator;

///
///  Clear the sync server configuration from the effective configuration.
///
- (void)clearSyncState;

@end
