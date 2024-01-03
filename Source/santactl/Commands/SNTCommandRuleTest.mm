/// Copyright 2024 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <map>
#include <utility>

#import "Source/common/SNTRule.h"
#import "Source/santactl/Commands/SNTCommandRule.h"

@interface SNTCommandRule (Testing)
+ (NSString *)stringifyRule:(SNTRule *)rule withColor:(BOOL)colorize;
@end

@interface SNTRule ()
@property(readwrite) NSUInteger timestamp;
@end

@interface SNTCommandRuleTest : XCTestCase
@end

@implementation SNTCommandRuleTest

- (void)testStringifyRule {
  std::map<std::pair<SNTRuleType, SNTRuleState>, NSString *> ruleCheckToString = {
    {{SNTRuleTypeUnknown, SNTRuleStateUnknown}, @"No rule exists with the given parameters"},
    {{SNTRuleTypeUnknown, SNTRuleStateAllow}, @"Allowed (Unknown)"},
    {{SNTRuleTypeUnknown, SNTRuleStateBlock}, @"Blocked (Unknown)"},
    {{SNTRuleTypeUnknown, SNTRuleStateSilentBlock}, @"Blocked (Unknown, Silent)"},
    {{SNTRuleTypeUnknown, SNTRuleStateRemove}, @"Unexpected rule state: 4 (Unknown)"},
    {{SNTRuleTypeUnknown, SNTRuleStateAllowCompiler}, @"Allowed (Unknown, Compiler)"},
    {{SNTRuleTypeUnknown, SNTRuleStateAllowTransitive},
     @"Allowed (Unknown, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

    {{SNTRuleTypeBinary, SNTRuleStateUnknown}, @"No rule exists with the given parameters"},
    {{SNTRuleTypeBinary, SNTRuleStateAllow}, @"Allowed (Binary)"},
    {{SNTRuleTypeBinary, SNTRuleStateBlock}, @"Blocked (Binary)"},
    {{SNTRuleTypeBinary, SNTRuleStateSilentBlock}, @"Blocked (Binary, Silent)"},
    {{SNTRuleTypeBinary, SNTRuleStateRemove}, @"Unexpected rule state: 4 (Binary)"},
    {{SNTRuleTypeBinary, SNTRuleStateAllowCompiler}, @"Allowed (Binary, Compiler)"},
    {{SNTRuleTypeBinary, SNTRuleStateAllowTransitive},
     @"Allowed (Binary, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

    {{SNTRuleTypeSigningID, SNTRuleStateUnknown}, @"No rule exists with the given parameters"},
    {{SNTRuleTypeSigningID, SNTRuleStateAllow}, @"Allowed (SigningID)"},
    {{SNTRuleTypeSigningID, SNTRuleStateBlock}, @"Blocked (SigningID)"},
    {{SNTRuleTypeSigningID, SNTRuleStateSilentBlock}, @"Blocked (SigningID, Silent)"},
    {{SNTRuleTypeSigningID, SNTRuleStateRemove}, @"Unexpected rule state: 4 (SigningID)"},
    {{SNTRuleTypeSigningID, SNTRuleStateAllowCompiler}, @"Allowed (SigningID, Compiler)"},
    {{SNTRuleTypeSigningID, SNTRuleStateAllowTransitive},
     @"Allowed (SigningID, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

    {{SNTRuleTypeCertificate, SNTRuleStateUnknown}, @"No rule exists with the given parameters"},
    {{SNTRuleTypeCertificate, SNTRuleStateAllow}, @"Allowed (Certificate)"},
    {{SNTRuleTypeCertificate, SNTRuleStateBlock}, @"Blocked (Certificate)"},
    {{SNTRuleTypeCertificate, SNTRuleStateSilentBlock}, @"Blocked (Certificate, Silent)"},
    {{SNTRuleTypeCertificate, SNTRuleStateRemove}, @"Unexpected rule state: 4 (Certificate)"},
    {{SNTRuleTypeCertificate, SNTRuleStateAllowCompiler}, @"Allowed (Certificate, Compiler)"},
    {{SNTRuleTypeCertificate, SNTRuleStateAllowTransitive},
     @"Allowed (Certificate, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},

    {{SNTRuleTypeTeamID, SNTRuleStateUnknown}, @"No rule exists with the given parameters"},
    {{SNTRuleTypeTeamID, SNTRuleStateAllow}, @"Allowed (TeamID)"},
    {{SNTRuleTypeTeamID, SNTRuleStateBlock}, @"Blocked (TeamID)"},
    {{SNTRuleTypeTeamID, SNTRuleStateSilentBlock}, @"Blocked (TeamID, Silent)"},
    {{SNTRuleTypeTeamID, SNTRuleStateRemove}, @"Unexpected rule state: 4 (TeamID)"},
    {{SNTRuleTypeTeamID, SNTRuleStateAllowCompiler}, @"Allowed (TeamID, Compiler)"},
    {{SNTRuleTypeTeamID, SNTRuleStateAllowTransitive},
     @"Allowed (TeamID, Transitive)\nlast access date: 2023-03-08 20:26:40 +0000"},
  };

  SNTRule *rule = [[SNTRule alloc] init];
  rule.timestamp = 700000000;  // time interval since reference date

  for (const auto &[typeAndState, want] : ruleCheckToString) {
    rule.type = typeAndState.first;
    rule.state = typeAndState.second;

    NSString *got = [SNTCommandRule stringifyRule:rule withColor:NO];
    XCTAssertEqualObjects(got, want);
  }
}
@end
