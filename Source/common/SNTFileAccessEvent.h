/// Copyright 2023 Google LLC
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

#import "Source/common/SNTStoredEvent.h"

///
///  Represents an event stored in the database.
///
@interface SNTFileAccessEvent : SNTStoredEvent <NSSecureCoding>

///
/// The watched path that was accessed
///
@property NSString *accessedPath;

///
/// The rule version and name that were violated
///
@property NSString *ruleVersion;
@property NSString *ruleName;

///
/// If the process is part of a bundle, the name of the application
///
@property NSString *application;

///
/// A string representing the publisher based on the signingChain
///
@property(readonly) NSString *publisherInfo;

///
/// Return an array of the underlying SecCertificateRef's of the signingChain
///
/// WARNING: If the refs need to be used for a long time be careful to properly
/// CFRetain/CFRelease the returned items.
///
@property(readonly) NSArray *signingChainCertRefs;

@end
