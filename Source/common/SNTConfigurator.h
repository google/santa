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

#import "SNTCommonEnums.h"

///
///  Singleton that provides an interface for managing configuration values on disk
///  @note This class is designed as a singleton but that is not strictly enforced.
///
@interface SNTConfigurator : NSObject

///  Default config file path
extern NSString *const kDefaultConfigFilePath;

#pragma mark - Daemon Settings

///
///  The operating mode.
///
@property(nonatomic) SNTClientMode clientMode;

///
///  The regex of paths to log file changes for. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotalL) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(nonatomic) NSRegularExpression *fileChangesRegex;

///
///  The regex of whitelisted paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(nonatomic) NSRegularExpression *whitelistPathRegex;

///
///  The regex of blacklisted paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(nonatomic) NSRegularExpression *blacklistPathRegex;

///
///  Enable __PAGEZERO protection, defaults to YES
///  If this flag is set to NO, 32-bit binaries that are missing
///  the __PAGEZERO segment will not be blocked.
///
@property(readonly, nonatomic) BOOL enablePageZeroProtection;

#pragma mark - GUI Settings

///
///  The URL to open when the user clicks "More Info..." when opening Santa.app.
///  If unset, the button will not be displayed.
///
@property(readonly, nonatomic) NSURL *moreInfoURL;

///
///  When the user gets a block notification, a button can be displayed which will
///  take them to a web page with more information about that event.
///  There are two properties, one for individual binaries and one for binaries that are part
///  of a bundle. If the latter is not set the former will be used.
///
///  This property contains a kind of format string to be turned into the URL to send them to.
///  The following sequences will be replaced in the final URL:
///
///  %file_sha%    -- SHA-256 of the file that was blocked.
///  %machine_id%  -- ID of the machine.
///  %username%    -- executing user.
///  %bundle_id%   -- bundle id of the binary, if applicable.
///  %bundle_ver%  -- bundle version of the binary, if applicable.
///
///  @note: This is not an NSURL because the format-string parsing is done elsewhere.
///
///  If this item isn't set, the Open Event button will not be displayed.
///
@property(readonly, nonatomic) NSString *eventDetailURL;
@property(readonly, nonatomic) NSString *eventDetailBundleURL;

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
///  If YES, mid-execution event uploads are skipped.
///  This property is never stored on disk.
///
@property BOOL syncBackOff;

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
///  Designated initializer.
///
///  @param filePath The path to the file to use as a backing store.
///
- (instancetype)initWithFilePath:(NSString *)filePath;

///
///  Re-read config data from disk.
///
- (void)reloadConfigData;

@end
