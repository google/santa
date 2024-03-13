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

/**
 * This file declares two types that are mirrors of each other.
 *
 * The C struct serves as a way to group and pass valid rule identifiers around
 * in order to minimize interface changes needed when new rule types are added
 * and also alleviate the need to allocate a short lived object.
 *
 * The Objective C class is used for an XPC boundary to easily pass rule
 * identifiers between Santa components.
 */

#import <Foundation/Foundation.h>

struct RuleIdentifiers {
  NSString *cdhash;
  NSString *binarySHA256;
  NSString *signingID;
  NSString *certificateSHA256;
  NSString *teamID;
};

@interface SNTRuleIdentifiers : NSObject <NSSecureCoding>
@property(readonly) NSString *cdhash;
@property(readonly) NSString *binarySHA256;
@property(readonly) NSString *signingID;
@property(readonly) NSString *certificateSHA256;
@property(readonly) NSString *teamID;

/// Please use `initWithRuleIdentifiers:`
- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithRuleIdentifiers:(struct RuleIdentifiers)identifiers
  NS_DESIGNATED_INITIALIZER;

- (struct RuleIdentifiers)toStruct;

@end
