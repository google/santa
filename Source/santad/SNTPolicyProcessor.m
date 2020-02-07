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

#import "Source/santad/SNTPolicyProcessor.h"

#import <MOLCodesignChecker/MOLCodesignChecker.h>

#include "Source/common/SNTLogging.h"

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

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

- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                        fileSHA256:(nullable NSString *)fileSHA256 {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = fileSHA256 ?: fileInfo.SHA256;

  // If the binary is a critical system binary, don't check its signature.
  // The binary was validated at startup when the rule table was initialized.
  SNTCachedDecision *systemCd = self.ruleTable.criticalSystemBinaries[cd.sha256];
  if (systemCd) return systemCd;

  // Grab the code signature, if there's an error don't try to capture
  // any of the signature details.
  NSError *csInfoError;
  MOLCodesignChecker *csInfo = [fileInfo codesignCheckerWithError:&csInfoError];
  if (csInfoError) csInfo = nil;

  cd.certSHA256 = csInfo.leafCertificate.SHA256;
  cd.certCommonName = csInfo.leafCertificate.commonName;
  cd.certChain = csInfo.certificates;
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
          case SNTRuleStateWhitelistCompiler:
            // If transitive whitelisting is enabled, then SNTRuleStateWhiteListCompiler rules
            // become SNTEventStateAllowCompiler decisions.  Otherwise we treat the rule as if
            // it were SNTRuleStateWhitelist.
            if ([[SNTConfigurator configurator] enableTransitiveWhitelisting]) {
              cd.decision = SNTEventStateAllowCompiler;
            } else {
              cd.decision = SNTEventStateAllowBinary;
            }
            return cd;
          case SNTRuleStateWhitelistTransitive:
            // If transitive whitelisting is enabled, then SNTRuleStateWhitelistTransitive
            // rules become SNTEventStateAllowTransitive decisions.  Otherwise, we treat the
            // rule as if it were SNTRuleStateUnknown.
            if ([[SNTConfigurator configurator] enableTransitiveWhitelisting]) {
              cd.decision = SNTEventStateAllowTransitive;
              return cd;
            } else {
              rule.state = SNTRuleStateUnknown;
            }
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
            // intentional fallthrough
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

- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo {
  return [self decisionForFileInfo:fileInfo fileSHA256:nil];
}

- (nonnull SNTCachedDecision *)decisionForFilePath:(nonnull NSString *)filePath
                                        fileSHA256:(nullable NSString *)fileSHA256 {
  SNTFileInfo *fileInfo;
  NSError *error;
  fileInfo = [[SNTFileInfo alloc] initWithPath:filePath error:&error];
  if (!fileInfo) LOGW(@"Failed to read file %@: %@", filePath, error.localizedDescription);
  return [self decisionForFileInfo:fileInfo fileSHA256:fileSHA256];
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
