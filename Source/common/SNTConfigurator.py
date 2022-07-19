import SNTConfiguratorGenerator

c = SNTConfiguratorGenerator.ConfigGenerator()

#
#  The operating mode. Defaults to MONITOR.
#
c.RegisterPropertyCustom('ClientMode', 'SNTClientMode', """
  SNTClientMode cm = [self.syncState[@"ClientMode"] longLongValue];
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown) {
    return cm;
  }
  cm = [self.configState[@"ClientMode"] longLongValue];
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown) {
    return cm;
  }
  return SNTClientModeMonitor;
""", setter="""
  if (v == SNTClientModeMonitor || v == SNTClientModeLockdown) {
    [self updateSyncStateForKey:@"ClientMode" value:@(v)];
  }
""", transportType="NSNumber")

#
#  Defines how event logs are stored. Options are:
#    SNTEventLogTypeSyslog "syslog": Sent to ASL or ULS (if built with the 10.12 SDK or later).
#    SNTEventLogTypeFilelog "file": Sent to a file on disk. Use eventLogPath to specify a path.
#    SNTEventLogTypeNull "null": Logs nothing
#    SNTEventLogTypeProtobuf "protobuf": (BETA) Sent to a file on disk, using maildir format. Use
#      mailDirectory to specify a path. Use mailDirectoryFileSizeThresholdKB,
#      mailDirectorySizeThresholdMB and mailDirectoryEventMaxFlushTimeSec to configure
#      additional maildir format settings.
#    Defaults to SNTEventLogTypeFilelog.
#    For mobileconfigs use EventLogType as the key and syslog or filelog strings as the value.
#
#  @note: This property is KVO compliant, but should only be read once at santad startup.
#
c.RegisterPropertyCustom('EventLogType', 'SNTEventLogType', """
  NSString *logType = [self.configState[@"EventLogType"] lowercaseString];
  if ([logType isEqualToString:@"protobuf"]) {
    return SNTEventLogTypeProtobuf;
  } else if ([logType isEqualToString:@"syslog"]) {
    return SNTEventLogTypeSyslog;
  } else if ([logType isEqualToString:@"null"]) {
    return SNTEventLogTypeNull;
  } else if ([logType isEqualToString:@"file"]) {
    return SNTEventLogTypeFilelog;
  } else {
    return SNTEventLogTypeFilelog;
  }
""")

#
#  If eventLogType is set to Filelog, eventLogPath will provide the path to save logs.
#  Defaults to /var/db/santa/santa.log.
#
#  @note: This property is KVO compliant, but should only be read once at santad startup.
#
c.RegisterProperty('EventLogPath', 'NSString *', '/var/db/santa/santa.log')

#
#  If eventLogType is set to protobuf, mailDirectory will provide the base path used for
#  saving logs using the maildir format.
#  Defaults to /var/db/santa/mail.
#
#  @note: This property is KVO compliant, but should only be read once at santad startup.
#
c.RegisterProperty('MailDirectory', 'NSString *', '/var/db/santa/mail')

#
#  If eventLogType is set to protobuf, mailDirectoryFileSizeThresholdKB sets the per-file size
#  limit for files saved in the mailDirectory.
#  Defaults to 100.
#
#  @note: This property is KVO compliant, but should only be read once at santad startup.
#
c.RegisterProperty('MailDirectoryFileSizeThresholdKB', 'NSUInteger', 100)

#
#  If eventLogType is set to protobuf, mailDirectorySizeThresholdMB sets the total size
#  limit for all files saved in the mailDirectory.
#  Defaults to 500.
#
#  @note: This property is KVO compliant, but should only be read once at santad startup.
#
c.RegisterProperty('MailDirectorySizeThresholdMB', 'NSUInteger', 500)

#
#  If eventLogType is set to protobuf, mailDirectoryEventMaxFlushTimeSec sets the maximum amount
#  of time an event will be stored in memory before being written to disk.
#  Defaults to 5.0.
#
#  @note: This property is KVO compliant, but should only be read once at santad startup.
#
c.RegisterProperty('MailDirectoryEventMaxFlushTimeSec', 'float', 5.0)

#
#  A set of static rules that should always apply. These can be used as a
#  fallback set of rules for management tools that should always be allowed to
#  run even if a sync server does something unexpected. It can also be used
#  as the sole source of rules, distributed with an MDM.
#
#  The value of this key should be an array containing dictionaries. Each
#  dictionary should contain the same keys used for syncing, e.g:
#
#  <key>StaticRules</key>
#  <array>
#    <dict>
#      <key>identifier</key>
#      <string>binary sha256, certificate sha256, team ID</string>
#      <key>rule_type</key>
#      <string>BINARY</string>  (one of BINARY, CERTIFICATE or TEAMID)
#      <key>policy</key>
#      <string>BLOCKLIST</string>  (one of ALLOWLIST, ALLOWLIST_COMPILER, BLOCKLIST, SILENT_BLOCKLIST)
#    </dict>
#  </array>
#
#  The return of this property is a dictionary where the keys are the
#  identifiers of each rule, with the SNTRule as a value
#
c.RegisterPropertyCustom('StaticRules', 'NSDictionary *', """
return self.cachedStaticRules;
""", transportType='NSArray')

#
#  The regex of paths to log file changes for. Regexes are specified in ICU format.
#
#  The regex flags IXSM can be used, though the s (dotalL) and m (multiline) flags are
#  pointless as a path only ever has a single line.
#  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
#
c.RegisterProperty('FileChangesRegex', 'NSRegularExpression *')

#
#  A list of ignore prefixes which are checked against a tree.
#  This is more performant than FileChangesRegex when ignoring whole directory trees.
#
#  For example adding a prefix of "/private/tmp/" will turn off file change log generation
#  in-kernel for that entire tree. Since they are ignored by the kernel, they never reach santad
#  and are not seen by the fileChangesRegex. Note the trailing "/", without it any file or
#  directory starting with "/private/tmp" would be ignored.
#
#  By default "/." and "/dev/" are added.
#
#  An ASCII character uses 1 node. An UTF-8 encoded Unicode character uses 1-4 nodes.
#  Prefixes are added to the running config in-order, one by one. The prefix will be ignored if
#  (the running config's current size) + (the prefix's size) totals up to more than 1024 nodes.
#  The running config is stored in a prefix tree.
#  Prefixes that share prefixes are effectively de-duped; their shared node sized components only
#  take up 1 node. For example these 3 prefixes all have a common prefix of "/private/".
#  They will only take up 21 nodes instead of 39.
#
#  "/private/tmp/"
#  "/private/var/"
#  "/private/new/"
#
#                                                              -> [t] -> [m] -> [p] -> [/]
#
#  [/] -> [p] -> [r] -> [i] -> [v] -> [a] -> [t] -> [e] -> [/] -> [v] -> [a] -> [r] -> [/]
#
#                                                              -> [n] -> [e] -> [w] -> [/]
#
#  Prefixes with Unicode characters work similarly. Assuming a UTF-8 encoding these two prefixes
#  are actually the same for the first 3 nodes. They take up 7 nodes instead of 10.
#
#  "/🤘"
#  "/🖖"
#
#                          -> [0xa4] -> [0x98]
#
#  [/] -> [0xf0] -> [0x9f]
#
#                          -> [0x96] -> [0x96]
#
#  To disable file change logging completely add "/".
#  TODO(bur): Make this default if no FileChangesRegex is set.
#
#  Filters are only applied on santad startup.
#  TODO(bur): Support add / remove of filters while santad is running.
#
c.RegisterProperty('FileChangesPrefixFilters', 'NSArray *')

#
#  Enable __PAGEZERO protection, defaults to YES
#  If this flag is set to NO, 32-bit binaries that are missing
#  the __PAGEZERO segment will not be blocked.
#
c.RegisterProperty('EnablePageZeroProtection', 'BOOL', True)

#
#  Enable bad signature protection, defaults to NO.
#  When enabled, a binary that is signed but has a bad signature (cert revoked, binary
#  tampered with, etc.) will be blocked regardless of client-mode unless a binary allowlist
#  rule exists.
#
c.RegisterProperty('EnableBadSignatureProtection', 'BOOL', False)

#
# Enabling this appends the Santa machine ID to the end of each log line. If nothing
# has been overriden, this is the host's UUID.
# Defaults to NO.
#
c.RegisterProperty('EnableMachineIDDecoration', 'BOOL', False)

#
#  Use an internal cache for decisions instead of relying on the caching
#  mechanism built-in to the EndpointSecurity framework. This may increase
#  performance, particularly when Santa is run alongside other system
#  extensions.
#  Has no effect if the system extension is not being used. Defaults to YES.
#
c.RegisterProperty('EnableSysxCache', 'BOOL', True)

#
# The text to display when opening Santa.app.
# If unset, the default text will be displayed.
#
c.RegisterProperty('AboutText', 'NSString *')

#
#  The URL to open when the user clicks "More Info..." when opening Santa.app.
#  If unset, the button will not be displayed.
#
c.RegisterProperty('MoreInfoURL', 'NSURL *')

#
#  When the user gets a block notification, a button can be displayed which will
#  take them to a web page with more information about that event.
#
#  This property contains a kind of format string to be turned into the URL to send them to.
#  The following sequences will be replaced in the final URL:
#
#  %file_sha%    -- SHA-256 of the file that was blocked.
#  %machine_id%  -- ID of the machine.
#  %username%    -- executing user.
#  %serial%      -- System's serial number.
#  %uuid%        -- System's UUID.
#  %hostname%    -- System's full hostname.
#
#  @note: This is not an NSURL because the format-string parsing is done elsewhere.
#
#  If this item isn't set, the Open Event button will not be displayed.
#
c.RegisterProperty('EventDetailURL', 'NSString *')


c.RegisterProperty('FailClosed', 'BOOL', False)

#
#  The regex of allowed paths. Regexes are specified in ICU format.
#
#  The regex flags IXSM can be used, though the s (dotall) and m (multiline)
#  flags are pointless as a path only ever has a single line. If the regex
#  doesn't begin with ^ to match from the beginning of the line, it will be
#  added.
#
c.RegisterReadwriteProperty(['AllowedPathRegex', 'WhitelistRegex'], 'NSRegularExpression *')

#
#  The regex of blocked paths. Regexes are specified in ICU format.
#
#  The regex flags IXSM can be used, though the s (dotall) and m (multiline)
#  flags are pointless as a path only ever has a single line. If the regex
#  doesn't begin with ^ to match from the beginning of the line, it will be
#  added.
#
c.RegisterReadwriteProperty(['BlockedPathRegex', 'BlacklistRegex'], 'NSRegularExpression *')


#
#  Related to the above property, this string represents the text to show on the button.
#
c.RegisterProperty('EventDetailText', 'NSString *')

#
#  In lockdown mode this is the message shown to the user when an unknown binary
#  is blocked. If this message is not configured, a reasonable default is provided.
#
c.RegisterProperty('UnknownBlockMessage', 'NSString *')

#
#  This is the message shown to the user when a binary is blocked because of a rule,
#  if that rule doesn't provide a custom message. If this is not configured, a reasonable
#  default is provided.
#
c.RegisterProperty('BannedBlockMessage', 'NSString *')

#
# This is the message shown to the user when a USB storage device's mount is denied
# from the BlockUSB configuration setting. If not configured, a reasonable
# default is provided.
#
c.RegisterProperty('BannedUSBBlockMessage', 'NSString *')

#
# This is the message shown to the user when a USB storage device's mount is forcibly
# remounted to a different set of permissions from the BlockUSB and RemountUSBMode
# configuration settings. If not configured, a reasonable default is provided.
#
c.RegisterProperty('RemountUSBBlockMessage', 'NSString *')

#
#  The notification text to display when the client goes into MONITOR mode.
#  Defaults to "Switching into Monitor mode"
#
c.RegisterProperty('ModeNotificationMonitor', 'NSString *')

#
#  The notification text to display when the client goes into LOCKDOWN mode.
#  Defaults to "Switching into Lockdown mode"
#
c.RegisterProperty('ModeNotificationLockdown', 'NSString *')

#
#  The base URL of the sync server.
#
c.RegisterProperty('SyncBaseURL', 'NSURL *')

#
#  Proxy settings for syncing.
#  This dictionary is passed directly to NSURLSession. The allowed keys
#  are loosely documented at
#  https://developer.apple.com/documentation/cfnetwork/global_proxy_settings_constants.
#
c.RegisterProperty('SyncProxyConfig', 'NSDictionary *')

#
#  The machine owner, used in syncing.
#  If MachineOwner is set, that is used.
#  Otherwise, if MachineOwnerPlist and MachineOwnerKey are set, the specified
#  key is read from the specified plist and if that is a string, it is used.
#
c.RegisterPropertyCustom(['MachineOwner', 'MachineOwnerPlist', 'MachineOwnerKey'], 'NSString *', """
  NSString *machineOwner = self.configState[@"MachineOwner"];
  if (machineOwner.length) return machineOwner;

  NSString *plistPath = self.configState[@"MachineOwnerPlist"];
  NSString *plistKey = self.configState[@"MachineOwnerKey"];
  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineOwner = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }
  return machineOwner ?: @"";
""")

#
#  The last date of a successful full sync.
#
c.RegisterReadwriteProperty('FullSyncLastSuccess', 'NSDate *')

#
#  The last date of a successful rule sync.
#
c.RegisterReadwriteProperty('RuleSyncLastSuccess', 'NSDate *')

#
#  If YES a clean sync is required.
#
c.RegisterReadwriteProperty('SyncCleanRequired', 'BOOL')

#
# USB Mount Blocking. Defaults to false.
#
c.RegisterReadwriteProperty('BlockUSBMount', 'BOOL', False)

#
# Comma-seperated `$ mount -o` arguments used for forced remounting of USB devices. Default
# to fully allow/deny without remounting if unset.
#
c.RegisterReadwriteProperty('RemountUSBMode', 'NSArray *')

#
# When `blockUSBMount` is set, this is the message shown to the user when a device is blocked
# If this message is not configured, a reasonable default is provided.
#
c.RegisterProperty(['usbBlockMessage', 'USBBlockMessage'], 'NSString *')

#
#  If set, this over-rides the default machine ID used for syncing.
#  First, the MachineID key is used if non-empty.
#  Otherwise, if MachineIDPlist and MachineIDKey are set, the specified key
#  is read from the specified plist and if a string is returned, that is used.
#
c.RegisterPropertyCustom(['MachineID', 'MachineIDPlist', 'MachineIDKey'], 'NSString *', """
  NSString *machineId = self.configState[@"MachineID"];
  if (machineId.length) return machineId;

  NSString *plistPath = self.configState[@"MachineIDPlist"];
  NSString *plistKey = self.configState[@"MachineIDKey"];

  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineId = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }
  return machineId.length ? machineId : [SNTSystemInfo hardwareUUID];
""")

#
#  If YES, enables bundle detection for blocked events. This property is not stored on disk.
#  Its value is set by a sync server that supports bundles. Defaults to NO.
#  TODO: VERIFY THE NON-STORED ATTRIBUTE HERE
#
c.RegisterReadwriteProperty('EnableBundles', 'BOOL', False)

#
#  If YES, binaries marked with SNTRuleStateAllowCompiler rules are allowed to transitively
#  allow any executables that they produce.  If NO, SNTRuleStateAllowCompiler rules are
#  interpreted as if they were simply SNTRuleStateAllow rules.  Defaults to NO.
#
c.RegisterReadwriteProperty('EnableTransitiveRules', 'BOOL', False)

#
#  If set, this is valid PEM containing one or more certificates to be used to evaluate the
#  server's SSL chain, overriding the list of trusted CAs distributed with the OS.
#
c.RegisterProperty('SyncServerAuthRootsData', 'NSData *')

#
#  This property is the same as the above but is a file on disk containing the PEM data.
#
c.RegisterProperty('SyncServerAuthRootsFile', 'NSString *')

#
#  If set, this contains the location of a PKCS#12 certificate to be used for sync authentication.
#
c.RegisterProperty('SyncClientAuthCertificateFile', 'NSString *')

#
#  Contains the password for the pkcs#12 certificate.
#
c.RegisterProperty('SyncClientAuthCertificatePassword', 'NSString *')

#
#  If set, this is the Common Name of a certificate in the System keychain to be used for
#  sync authentication. The corresponding private key must also be in the keychain.
#
c.RegisterProperty(['SyncClientAuthCertificateCn', 'SyncClientAuthCertificateCN'], 'NSString *')

#
#  If set, this is the Issuer Name of a certificate in the System keychain to be used for
#  sync authentication. The corresponding private key must also be in the keychain.
#
c.RegisterProperty('SyncClientAuthCertificateIssuer', 'NSString *')

#
#  If true, syncs will upload events when a clean sync is requested. Defaults to false.
#
c.RegisterProperty('EnableCleanSyncEventUpload', 'BOOL', False)

#
#  If true, events will be uploaded for all executions, even those that are allowed.
#  Use with caution, this generates a lot of events. Defaults to false.
#
c.RegisterReadwriteProperty('EnableAllEventUpload', 'BOOL', False)

#
#  If true, events will *not* be uploaded for ALLOW_UNKNOWN events for clients in Monitor mode.
#
c.RegisterReadwriteProperty('DisableUnknownEventUpload', 'BOOL', False)

#
#  If true, forks and exits will be logged. Defaults to false.
#
c.RegisterProperty('EnableForkAndExitLogging', 'BOOL', False)

#
#  If true, ignore actions from other endpoint security clients. Defaults to false.
#
c.RegisterProperty('IgnoreOtherEndpointSecurityClients', 'BOOL', False)

#
#  If true, debug logging will be enabled for all Santa components. Defaults to false.
#  Passing --debug as an executable argument will enable debug logging for that specific
#  component.
#
c.RegisterPropertyCustom('EnableDebugLogging', 'BOOL', """
  NSNumber *number = self.configState[@"EnableDebugLogging"];
  return [number boolValue] || self.debugFlag;
""")

#
#  If true, compressed requests from "santactl sync" will set "Content-Encoding" to "zlib"
#  instead of the new default "deflate". If syncing with Upvote deployed at commit 0b4477d
#  or below, set this option to true.
#  Defaults to false.
#
c.RegisterProperty('EnableBackwardsCompatibleContentEncoding', 'BOOL', False)

#
#  Contains the FCM project name.
#
c.RegisterProperty(['fcmProject', 'FCMProject'], 'NSString *')

#
#  Contains the FCM project entity.
#
c.RegisterProperty(['fcmEntity', 'FCMEntity'], 'NSString *')

#
#  Contains the FCM project API key.
#
c.RegisterProperty(['fcmAPIKey', 'FCMAPIKey'], 'NSString *')

#
#  True if fcmProject, fcmEntity and fcmAPIKey are all set. Defaults to false.
#
c.RegisterPropertyCustom('fcmEnabled', 'BOOL', """
  return (self.fcmProject.length && self.fcmEntity.length && self.fcmAPIKey.length);
""")

#
# URL describing where metrics are exported.
#
c.RegisterProperty('MetricURL', 'NSURL *')

#
# Extra Metric Labels to add to the metrics payloads.
#
c.RegisterProperty('ExtraMetricLabels', 'NSDictionary *')

#
# Duration in seconds of how often the metrics should be exported. Defaults to 30.
#
c.RegisterProperty('MetricExportInterval', 'NSUInteger', 30)

#
# Duration in seconds for metrics export timeout. Defaults to 30.
#
c.RegisterProperty('MetricExportTimeout', 'NSUInteger', 30)

#
# True if metricsFormat and metricsURL are set. False otherwise.
#
c.RegisterPropertyCustom('ExportMetrics', 'BOOL', """
  return self.metricFormat != SNTMetricFormatTypeUnknown && self.metricURL.absoluteString.length;
""")

#
# Format to export Metrics as.
#
c.RegisterPropertyCustom('MetricFormat', 'SNTMetricFormatType', """
  NSString *metricFormat = [self.configState[@"MetricFormat"] lowercaseString];
  if ([metricFormat isEqualToString:@"rawjson"]) {
    return SNTMetricFormatTypeRawJSON;
  } else if ([metricFormat isEqualToString:@"monarchjson"]) {
    return SNTMetricFormatTypeMonarchJSON;
  } else {
    return SNTMetricFormatTypeUnknown;
  }
""")


c.Generate()
