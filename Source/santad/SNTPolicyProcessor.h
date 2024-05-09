/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <MOLCertificate/MOLCertificate.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTRule.h"

@class MOLCodesignChecker;
@class SNTCachedDecision;
@class SNTFileInfo;
@class SNTRuleTable;

///
///  Creates SNTCachedDecision objects from a SNTFileInfo object or a file path. Decisions are based
///  on any existing rules for that specific binary, its signing certificate and the operating mode
///  of santad.
///
@interface SNTPolicyProcessor : NSObject

///
///  @param ruleTable The rule table to be used for every decision
///
- (nullable instancetype)initWithRuleTable:(nonnull SNTRuleTable *)ruleTable;

///
///  Convenience initializer. Will obtain the teamID and construct the signingID
///  identifier if able.
///
///  IMPORTANT: The lifetimes of arguments to `entitlementsFilterCallback` are
///  only guaranteed for the duration of the call to the block. Do not perform
///  any async processing without extending their lifetimes.
///
- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                     targetProcess:(nonnull const es_process_t *)targetProc
                        entitlementsFilterCallback:
                          (NSDictionary *_Nullable (^_Nonnull)(
                            const char *_Nullable teamID,
                            NSDictionary *_Nullable entitlements))entitlementsFilterCallback;

///
///  A wrapper for decisionForFileInfo:fileSHA256:certificateSHA256:. This method is slower as it
///  has to create the SNTFileInfo object. This is mainly used by the santactl binary because
///  SNTFileInfo is not SecureCoding compliant. If the SHA256 hash of the file has already been
///  calculated, use the fileSHA256 parameter to save a second calculation of the hash.
///
- (nonnull SNTCachedDecision *)decisionForFilePath:(nonnull NSString *)filePath
                                       identifiers:(nonnull SNTRuleIdentifiers *)identifiers;


///
/// Updates a decision for a given file and agent configuration.
///
/// Returns YES if the decision requires no futher processing NO otherwise.
- (BOOL)decision:(nonnull SNTCachedDecision *) cd 
                forRule:(nonnull SNTRule *) rule
    withTransitiveRules:(BOOL) transitive;

@end
