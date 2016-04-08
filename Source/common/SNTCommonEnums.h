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

///
///  These enums are used in various places throughout the Santa client code.
///  The integer values are also stored in the database and so shouldn't be changed.
///

typedef NS_ENUM(NSInteger, SNTRuleType) {
  SNTRuleTypeUnknown,

  SNTRuleTypeBinary = 1,
  SNTRuleTypeCertificate = 2,
};

typedef NS_ENUM(NSInteger, SNTRuleState) {
  SNTRuleStateUnknown,

  SNTRuleStateWhitelist = 1,
  SNTRuleStateBlacklist = 2,
  SNTRuleStateSilentBlacklist = 3,
  SNTRuleStateRemove = 4,
};

typedef NS_ENUM(NSInteger, SNTClientMode) {
  SNTClientModeUnknown,

  SNTClientModeMonitor = 1,
  SNTClientModeLockdown = 2,
};

typedef NS_ENUM(NSInteger, SNTEventState) {
  SNTEventStateUnknown,

  SNTEventStateAllowUnknown = 1,
  SNTEventStateAllowBinary = 2,
  SNTEventStateAllowCertificate = 3,
  SNTEventStateAllowScope = 4,

  SNTEventStateBlockUnknown = 5,
  SNTEventStateBlockBinary = 6,
  SNTEventStateBlockCertificate = 7,
  SNTEventStateBlockScope = 8,

  SNTEventStateRelatedBinary = 9,
};

typedef NS_ENUM(NSInteger, SNTRuleTableError) {
  SNTRuleTableErrorEmptyRuleArray,
  SNTRuleTableErrorInsertOrReplaceFailed,
  SNTRuleTableErrorInvalidRule,
  SNTRuleTableErrorMissingRequiredRule,
  SNTRuleTableErrorRemoveFailed
};

static const char *kKextPath = "/Library/Extensions/santa-driver.kext";
static const char *kSantaDPath = "/Library/Extensions/santa-driver.kext/Contents/MacOS/santad";
static const char *kSantaCtlPath = "/Library/Extensions/santa-driver.kext/Contents/MacOS/santactl";
