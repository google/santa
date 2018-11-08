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

#import "SNTCommonEnums.h"

///
///  Singleton that provides an interface for managing configuration values on disk
///  @note This class is designed as a singleton but that is not strictly enforced.
///  @note All properties are KVO compliant.
///
@interface SNTConfigurator : NSObject

#pragma mark - Daemon Settings

///
///  The operating mode.
///
@property(readonly, nonatomic) SNTClientMode clientMode;

///
///  Set the operating mode as received from a sync server.
///
- (void)setSyncServerClientMode:(SNTClientMode)newMode;

///
///  The regex of whitelisted paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(readonly, nonatomic) NSRegularExpression *whitelistPathRegex;

///
///  Set the regex of whitelisted paths as received from a sync server.
///
- (void)setSyncServerWhitelistPathRegex:(NSRegularExpression *)re;

///
///  The regex of blacklisted paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(readonly, nonatomic) NSRegularExpression *blacklistPathRegex;

///
///  Set the regex of blacklisted paths as received from a sync server.
///
- (void)setSyncServerBlacklistPathRegex:(NSRegularExpression *)re;

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
/// Enabling this appends the Santa machine ID to the end of each log line. If nothing
/// has been overriden, this is the host's UUID.
/// Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableMachineIDDecoration;

#pragma mark - GUI Settings

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
///  If set, this over-rides the default machine ID used for syncing.
///
@property(readonly, nonatomic) NSString *machineID;

///
///  If YES, enables bundle detection for blocked events. This property is not stored on disk.
///  Its value is set by a sync server that supports bundles. Defaults to NO.
///
@property BOOL enableBundles;

#pragma mark Transitive Whitelisting Settings

///
///  If YES, binaries marked with SNTRuleStateWhitelistCompiler rules are allowed to transitively
///  whitelist any executables that they produce.  If NO, SNTRuleStateWhitelistCompiler rules are
///  interpreted as if they were simply SNTRuleStateWhitelist rules.  Defaults to NO.
///
@property BOOL enableTransitiveWhitelisting;

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
///  Retrieve an initialized singleton configurator object using the default file path.
///
+ (instancetype)configurator;

///
///  Clear the sync server configuration from the effective configuration.
///
- (void)clearSyncState;

@end
