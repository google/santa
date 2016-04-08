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

#ifndef SANTA__COMMON__COMMONENUMS_H
#define SANTA__COMMON__COMMONENUMS_H

///
///  These enums are used in various places throughout the Santa client code.
///  The integer values are also stored in the database and so shouldn't be changed.
///

typedef enum {
  RULETYPE_UNKNOWN,

  RULETYPE_BINARY = 1,
  RULETYPE_CERT = 2,

  RULETYPE_MAX
} santa_ruletype_t;

typedef enum {
  RULESTATE_UNKNOWN,

  RULESTATE_WHITELIST = 1,
  RULESTATE_BLACKLIST = 2,
  RULESTATE_SILENT_BLACKLIST = 3,
  RULESTATE_REMOVE = 4,

  RULESTATE_MAX
} santa_rulestate_t;

typedef enum {
  CLIENTMODE_UNKNOWN,

  CLIENTMODE_MONITOR = 1,
  CLIENTMODE_LOCKDOWN = 2,

  CLIENTMODE_MAX
} santa_clientmode_t;

typedef enum {
  EVENTSTATE_UNKNOWN,

  EVENTSTATE_ALLOW_UNKNOWN = 1,
  EVENTSTATE_ALLOW_BINARY = 2,
  EVENTSTATE_ALLOW_CERTIFICATE = 3,
  EVENTSTATE_ALLOW_SCOPE = 4,

  EVENTSTATE_BLOCK_UNKNOWN = 5,
  EVENTSTATE_BLOCK_BINARY = 6,
  EVENTSTATE_BLOCK_CERTIFICATE = 7,
  EVENTSTATE_BLOCK_SCOPE = 8,

  EVENTSTATE_RELATED_BINARY = 9,

  EVENTSTATE_MAX
} santa_eventstate_t;

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

#endif  // SANTA__COMMON__COMMONENUMS_H
