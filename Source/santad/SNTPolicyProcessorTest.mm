/// Copyright 2024 Google Inc. All rights reserved.
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

#include <Foundation/Foundation.h>
#import "Source/santad/SNTPolicyProcessor.h"

#import <XCTest/XCTest.h>
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTRule.h"

#import "Source/santad/SNTPolicyProcessor.h"

@interface SNTPolicyProcessorTest : XCTestCase
@property SNTPolicyProcessor *processor;
@end

@implementation SNTPolicyProcessorTest
- (void)setUp {
  self.processor = [[SNTPolicyProcessor alloc] init];
}

- (void)testRule:(SNTRule *)rule
   transitiveRules:(BOOL)transitiveRules
             final:(BOOL)final
           matches:(BOOL)matches
            silent:(BOOL)silent
  expectedDecision:(SNTEventState)decision {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  if (matches) {
    switch (rule.type) {
      case SNTRuleTypeBinary: cd.sha256 = rule.identifier; break;
      case SNTRuleTypeCertificate: cd.certSHA256 = rule.identifier; break;
      case SNTRuleTypeCDHash: cd.cdhash = rule.identifier; break;
      default: break;
    }
  } else {
    switch (rule.type) {
      case SNTRuleTypeBinary:
        cd.sha256 = @"2334567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        break;
      case SNTRuleTypeCertificate:
        cd.certSHA256 = @"2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        break;
      case SNTRuleTypeCDHash: cd.cdhash = @"b023fbe5361a5bbd793dc3889556e93f41ec9bb8"; break;
      default: break;
    }
  }
  BOOL decisionIsFinal = [self.processor decision:cd
                                          forRule:rule
                              withTransitiveRules:transitiveRules];
  XCTAssertEqual(cd.decision, decision);
  XCTAssertEqual(decisionIsFinal, final);
  XCTAssertEqual(cd.silentBlock, silent);
}

- (void)testDecisionForBlockByCDHashRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockCDHash];
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockCDHash];
}

- (void)testDecisionForSilentBlockByCDHashRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"SILENT_BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockCDHash];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockCDHash];
}

- (void)testDecisionForAllowbyCDHashRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCDHash];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCDHash];
}

- (void)testDecisionForBlockBySHA256RuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockBinary];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockBinary];
}

- (void)testDecisionForSilenBlockBySHA256RuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"SILENT_BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockBinary];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockBinary];
}

- (void)testDecisionForAllowBySHA256RuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowBinary];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowBinary];
}

- (void)testDecisionForSigningIDBlockRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"ABCDEFGHIJ:ABCDEFGHIJ",
    @"policy" : @"BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockSigningID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockSigningID];
}

// Signing ID rules
- (void)testDecisionForSigningIDSilentBlockRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"TEAMID1234:ABCDEFGHIJ",
    @"policy" : @"SILENT_BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockSigningID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockSigningID];
}

- (void)testDecisionForSigningIDAllowRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"TEAMID1234:ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowSigningID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowSigningID];
}

//  Certificate rules
- (void)testDecisionForCertificateBlockRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CERTIFICATE",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockCertificate];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockCertificate];
}

- (void)testDecisionForCertificateSilentBlockRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CERTIFICATE",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"SILENT_BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockCertificate];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockCertificate];
}

- (void)testDecisionForCertificateAllowRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CERTIFICATE",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCertificate];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCertificate];
}

// Team ID rules
- (void)testDecisionForTeamIDBlockRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"TEAMID",
    @"identifier" : @"TEAMID1234",
    @"policy" : @"BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockTeamID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateBlockTeamID];
}

- (void)testDecisionForTeamIDSilentBlockRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"TEAMID",
    @"identifier" : @"TEAMID1234",
    @"policy" : @"SILENT_BLOCKLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockTeamID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:YES
    expectedDecision:SNTEventStateBlockTeamID];
}

- (void)testDecisionForTeamIDAllowRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"TEAMID",
    @"identifier" : @"TEAMID1234",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowTeamID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowTeamID];
}

// Compiler rules
// CDHash
- (void)testDecisionForCDHashCompilerRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"ALLOWLIST_COMPILER"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCompiler];
  // Ensure disabling transitive rules results in a binary allow
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCDHash];
}

// SHA256
- (void)testDecisionForSHA256CompilerRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST_COMPILER"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCompiler];
  // Ensure disabling transitive rules results in a binary allow
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowBinary];
}

// SigningID
- (void)testDecisionForSigningIDCompilerRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"TEAMID1234:ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST_COMPILER"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowCompiler];
  // Ensure disabling transitive rules results in a Signing ID allow
  [self testRule:rule
     transitiveRules:NO
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowSigningID];
}

// Transitive allowlist rules
- (void)testDecisionForTransitiveAllowlistRuleMatches {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  rule.state = SNTRuleStateAllowTransitive;

  [self testRule:rule
     transitiveRules:YES
               final:YES
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateAllowTransitive];
  // Ensure that a transitive allowlist rule results in an
  // SNTEventStateUnknown if transitive rules are disabled.
  [self testRule:rule
     transitiveRules:NO
               final:NO
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateUnknown];
}

- (void)testEnsureANonMatchingRuleResultsInUnknown {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  rule.state = static_cast<SNTRuleState>(88888);  // Set to an invalid state

  [self testRule:rule
     transitiveRules:YES
               final:NO
             matches:NO
              silent:NO
    expectedDecision:SNTEventStateUnknown];

  [self testRule:rule
     transitiveRules:NO
               final:NO
             matches:YES
              silent:NO
    expectedDecision:SNTEventStateUnknown];
}

- (void)testEnsureCustomURLAndMessageAreSet {
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST",
    @"custom_msg" : @"Custom Message",
    @"custom_url" : @"https://example.com"
  }];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = rule.identifier;

  [self.processor decision:cd forRule:rule withTransitiveRules:YES];

  XCTAssertEqualObjects(cd.customMsg, @"Custom Message");
  XCTAssertEqualObjects(cd.customURL, @"https://example.com");
}

@end
