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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTKernelCommon.h"

#import <MOLCertificate/MOLCertificate.h>

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
///  @param certificateSHA256 A SHA256 hash of the signing certificate, can be nil.
///  @note If fileSHA256 and certificateSHA256 are both passed in, the most specific rule will be
///        returned. Binary rules take precedence over cert rules.
///  @note This method can also be used to generate a SNTCachedDecision object without any
///        artifacts on disk. Simply pass nil to fileInfo and pass in the desired SHA256s.
///
- (nonnull SNTCachedDecision *)decisionForFileInfo:(nullable SNTFileInfo *)fileInfo
                                        fileSHA256:(nullable NSString *)fileSHA256
                                 certificateSHA256:(nullable NSString *)certificateSHA256;

///
///  A wrapper for decisionForFileInfo:fileSHA256:certificateSHA256:. This method is slower as it
///  has to create the SNTFileInfo object. This is mainly used by the santactl binary because
///  SNTFileInfo is not SecureCoding compliant. If the SHA256 hash of the file has already been
///  calculated, use the fileSHA256 parameter to save a second calculation of the hash.
///
- (nonnull SNTCachedDecision *)decisionForFilePath:(nullable NSString *)filePath
                                        fileSHA256:(nullable NSString *)fileSHA256
                                 certificateSHA256:(nullable NSString *)certificateSHA256;

@end
