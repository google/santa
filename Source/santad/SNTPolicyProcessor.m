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

#import "SNTPolicyProcessor.h"

#include "SNTLogging.h"

#import "SNTCachedDecision.h"
#import "SNTConfigurator.h"
#import "SNTFileInfo.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"

@interface SNTPolicyProcessor()
@property SNTRuleTable *ruleTable;
@end

@implementation SNTPolicyProcessor

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable {
  self = [super init];
  if (self) {
    _ruleTable = ruleTable;
  }
  return self;
}

- (SNTCachedDecision *)decisionForFileInfo:(SNTFileInfo *)fileInfo
                                fileSHA256:(NSString *)fileSHA256
                         certificateSHA256:(NSString *)certificateSHA256 {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = fileSHA256 ?: fileInfo.SHA256;
  cd.certSHA256 = certificateSHA256;
  cd.quarantineURL = fileInfo.quarantineDataURL;

  SNTRule *rule = [self.ruleTable ruleForBinarySHA256:cd.sha256
                                    certificateSHA256:cd.certSHA256];
  if (rule) {
    switch (rule.type) {
      case SNTRuleTypeBinary:
        switch (rule.state) {
          case SNTRuleStateWhitelist:
            cd.decision = SNTEventStateAllowBinary;
            return cd;
          case SNTRuleStateSilentBlacklist:
            cd.silentBlock = YES;
          case SNTRuleStateBlacklist:
            cd.customMsg = rule.customMsg;
            cd.decision = SNTEventStateBlockBinary;
            return cd;
          default: break;
        }
        break;
      case SNTRuleTypeCertificate:
        switch (rule.state) {
          case SNTRuleStateWhitelist:
            cd.decision = SNTEventStateAllowCertificate;
            return cd;
          case SNTRuleStateSilentBlacklist:
            cd.silentBlock = YES;
          case SNTRuleStateBlacklist:
            cd.customMsg = rule.customMsg;
            cd.decision = SNTEventStateBlockCertificate;
            return cd;
          default: break;
        }
        break;
      default:
        break;
    }
  }

  NSString *msg = [self fileIsScopeBlacklisted:fileInfo];
  if (msg) {
    cd.decisionExtra = msg;
    cd.decision = SNTEventStateBlockScope;
    return cd;
  }

  msg = [self fileIsScopeWhitelisted:fileInfo];
  if (msg) {
    cd.decisionExtra = msg;
    cd.decision = SNTEventStateAllowScope;
    return cd;
  }

  switch ([[SNTConfigurator configurator] clientMode]) {
    case SNTClientModeMonitor:
      cd.decision = SNTEventStateAllowUnknown;
      return cd;
    case SNTClientModeLockdown:
      cd.decision = SNTEventStateBlockUnknown;
      return cd;
    default:
      cd.decision = SNTEventStateBlockUnknown;
      return cd;
  }
}

- (SNTCachedDecision *)decisionForFilePath:(NSString *)filePath
                                fileSHA256:(NSString *)fileSHA256
                         certificateSHA256:(NSString *)certificateSHA256 {
  SNTFileInfo *fileInfo;
  if (filePath) {
    NSError *error;
    fileInfo = [[SNTFileInfo alloc] initWithPath:filePath error:&error];
    if (!fileInfo) LOGW(@"Failed to read file %@: %@", filePath, error.localizedDescription);
  }
  return [self decisionForFileInfo:fileInfo
                        fileSHA256:fileSHA256
                 certificateSHA256:certificateSHA256];
}

///
///  Checks whether the file at @c path is in-scope for checking with Santa.
///
///  Files that are out of scope:
///    + Non Mach-O files that are not part of an installer package.
///    + Files in whitelisted path.
///
///  @return @c YES if file is in scope, @c NO otherwise.
///
- (NSString *)fileIsScopeWhitelisted:(SNTFileInfo *)fi {
  if (!fi) return nil;
  
  // Determine if file is within a whitelisted path
  NSRegularExpression *re = [[SNTConfigurator configurator] whitelistPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Whitelist Regex";
  }

  // If file is not a Mach-O file, we're not interested.
  if (!fi.isMachO) {
    return @"Not a Mach-O";
  }

  return nil;
}

- (NSString *)fileIsScopeBlacklisted:(SNTFileInfo *)fi {
  if (!fi) return nil;
  
  NSRegularExpression *re = [[SNTConfigurator configurator] blacklistPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Blacklist Regex";
  }

  if ([[SNTConfigurator configurator] enablePageZeroProtection] && fi.isMissingPageZero) {
    return @"Missing __PAGEZERO";
  }

  return nil;
}

@end
