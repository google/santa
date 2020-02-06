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
#import <MOLCertificate/MOLCertificate.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTKernelCommon.h"

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
///  @param fileInfo A SNTFileInfo object.
///  @param fileSHA256 The pre-calculated SHA256 hash for the file, can be nil. If nil the hash will
///                    be calculated by this method from the filePath.
///
- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                        fileSHA256:(nullable NSString *)fileSHA256;

///  Convenience initializer with a nil hash.
- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo;

///
///  A wrapper for decisionForFileInfo:fileSHA256:certificateSHA256:. This method is slower as it
///  has to create the SNTFileInfo object. This is mainly used by the santactl binary because
///  SNTFileInfo is not SecureCoding compliant. If the SHA256 hash of the file has already been
///  calculated, use the fileSHA256 parameter to save a second calculation of the hash.
///
- (nonnull SNTCachedDecision *)decisionForFilePath:(nonnull NSString *)filePath
                                        fileSHA256:(nullable NSString *)fileSHA256;

@end
