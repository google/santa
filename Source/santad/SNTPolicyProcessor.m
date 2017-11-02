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

// SHAs for testing
NSString *clangSHA = @"b8d9c5f1446a6e90e0522b3c3ef69b81596b60343709b74277e739f8928feb86";
NSString *ldSHA = @"20c827271b3570992b632a035fa0181aea48038ee78847c2e8714b2dc429eb53";
NSString *goSHA = @"0bac9758770da7d92a9fd90b41aac04ebbb694968e3ef41aab3065bf176a899f";
NSString *gocompileSHA = @"7bc566785e7f7cf94e66debc22d77a466d24aad8474ac8f37f8210e5dd6978bc";
NSString *golinkSHA = @"9f16595bf07331ddb52968c67a478b3a4bc2a3c234a8d1b12341ff0d80b92e57";
NSString *codesignSHA = @"3f9fb24620412dedf21ac3ed898254a2dbb5145a79702d324f73631c154551b2";
NSString *xcodeSHA = @"dc4673a1577c424f5105f79cd03e332395c59b85ebbee234cf9b45bffac4447b";
NSString *ld8SHA = @"b569f3bfd77e4c540bb9b73b7135d16d49135634a8192e364ce88e8896dbd856";
NSString *blazeSHA = @"cb3696a1300d3b10c0dc53d0edb0437572ce3b8f53ec6670acd8a427d93e783d";

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

  //LOGI(@"#### decisionForFileInfo: %@", cd.sha256);

  SNTRule *rule = [self.ruleTable ruleForBinarySHA256:cd.sha256
                                    certificateSHA256:cd.certSHA256];

  // ld does final CLOSE for clang / gcc
  // or ld RENAME with clang / gcc if already exists.
  // also ld RENAME if Xcode without codesigning using xcodebuild
  // codesign does final CLOSE for Xcode with codesigning.
  // link does final CLOSE for go (either on tmp file if file already exists before RENAME,
  // or else on actual output file).

  if ([cd.sha256 isEqualToString:ldSHA] ||
      [cd.sha256 isEqualToString:ld8SHA] ||
      [cd.sha256 isEqualToString:golinkSHA] ||
      [cd.sha256 isEqualToString:codesignSHA] ||
      [cd.sha256 isEqualToString:blazeSHA]
      )
  {
    LOGI(@"#### decisionForFileInfo: SHA matches ld/link/codesign/blaze");
    rule.type = SNTRuleTypeBinary;
    rule.state = SNTRuleStateWhitelistCompiler;
  }

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
            cd.decision = SNTEventStateAllowCompiler;
            return cd;
          case SNTRuleStateWhitelistTransitive:
            cd.decision = SNTEventStateAllowTransitive;
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
          case SNTRuleStateWhitelistCompiler:
            cd.decision = SNTEventStateAllowCompiler;
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
