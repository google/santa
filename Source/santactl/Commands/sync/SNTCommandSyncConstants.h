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

extern NSString *const kXSRFToken;

extern NSString *const kSerialNumber;
extern NSString *const kHostname;
extern NSString *const kSantaVer;
extern NSString *const kOSVer;
extern NSString *const kOSBuild;
extern NSString *const kPrimaryUser;
extern NSString *const kRequestCleanSync;
extern NSString *const kBatchSize;
extern NSString *const kUploadLogsURL;
extern NSString *const kClientMode;
extern NSString *const kClientModeMonitor;
extern NSString *const kClientModeLockdown;
extern NSString *const kCleanSync;
extern NSString *const kWhitelistRegex;
extern NSString *const kBlacklistRegex;
extern NSString *const kBinaryRuleCount;
extern NSString *const kCertificateRuleCount;
extern NSString *const kCompilerRuleCount;
extern NSString *const kTransitiveRuleCount;
extern NSString *const kFCMToken;
extern NSString *const kFCMFullSyncInterval;
extern NSString *const kFCMGlobalRuleSyncDeadline;
extern NSString *const kEnableBundles;
extern NSString *const kEnableBundles_OLD;
extern NSString *const kEnableTransitiveWhitelisting;
extern NSString *const kEnableTransitiveWhitelisting_OLD;

extern NSString *const kEvents;
extern NSString *const kFileSHA256;
extern NSString *const kFilePath;
extern NSString *const kFileName;
extern NSString *const kExecutingUser;
extern NSString *const kExecutionTime;
extern NSString *const kDecision;
extern NSString *const kDecisionAllowUnknown;
extern NSString *const kDecisionAllowBinary;
extern NSString *const kDecisionAllowCertificate;
extern NSString *const kDecisionAllowScope;
extern NSString *const kDecisionBlockUnknown;
extern NSString *const kDecisionBlockBinary;
extern NSString *const kDecisionBlockCertificate;
extern NSString *const kDecisionBlockScope;
extern NSString *const kDecisionUnknown;
extern NSString *const kDecisionBundleBinary;
extern NSString *const kLoggedInUsers;
extern NSString *const kCurrentSessions;
extern NSString *const kFileBundleID;
extern NSString *const kFileBundlePath;
extern NSString *const kFileBundleExecutableRelPath;
extern NSString *const kFileBundleName;
extern NSString *const kFileBundleVersion;
extern NSString *const kFileBundleShortVersionString;
extern NSString *const kFileBundleHash;
extern NSString *const kFileBundleHashMilliseconds;
extern NSString *const kFileBundleBinaryCount;
extern NSString *const kPID;
extern NSString *const kPPID;
extern NSString *const kParentName;
extern NSString *const kSigningChain;
extern NSString *const kCertSHA256;
extern NSString *const kCertCN;
extern NSString *const kCertOrg;
extern NSString *const kCertOU;
extern NSString *const kCertValidFrom;
extern NSString *const kCertValidUntil;
extern NSString *const kQuarantineDataURL;
extern NSString *const kQuarantineRefererURL;
extern NSString *const kQuarantineTimestamp;
extern NSString *const kQuarantineAgentBundleID;
extern NSString *const kEventUploadBundleBinaries;

extern NSString *const kLogUploadField;

extern NSString *const kRules;
extern NSString *const kRuleSHA256;
extern NSString *const kRulePolicy;
extern NSString *const kRulePolicyWhitelist;
extern NSString *const kRulePolicyWhitelistCompiler;
extern NSString *const kRulePolicyBlacklist;
extern NSString *const kRulePolicySilentBlacklist;
extern NSString *const kRulePolicyRemove;
extern NSString *const kRuleType;
extern NSString *const kRuleTypeBinary;
extern NSString *const kRuleTypeCertificate;
extern NSString *const kRuleCustomMsg;
extern NSString *const kCursor;

extern NSString *const kBackoffInterval;

extern NSString *const kFullSync;
extern NSString *const kRuleSync;
extern NSString *const kConfigSync;
extern NSString *const kLogSync;

extern const NSUInteger kDefaultEventBatchSize;

///
///  kDefaultFullSyncInterval
///  kDefaultFCMFullSyncInterval
///  kDefaultFCMGlobalRuleSyncDeadline
///
///  Are represented in seconds
///
extern const NSUInteger kDefaultFullSyncInterval;
extern const NSUInteger kDefaultFCMFullSyncInterval;
extern const NSUInteger kDefaultFCMGlobalRuleSyncDeadline;

