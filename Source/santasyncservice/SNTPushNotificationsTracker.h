/// Copyright 2022 Google Inc. All rights reserved.
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
///    limitations under the License

#import <Foundation/Foundation.h>

// SNTPushNotificationsTracker stores info from push notification messages. The binary/bundle hash
// is used as a key mapping to values that are themselves dictionaries. These dictionary values
// contain the name of the binary/bundle and a count of associated binary rules.
@interface SNTPushNotificationsTracker : NSObject

// Retrieve an initialized singleton SNTPushNotificationsTracker object.
// Use this instead of init.
+ (instancetype)tracker;

- (void)addNotification:(NSDictionary *)notification forHash:(NSString *)hash;
- (void)removeNotificationsForHashes:(NSArray<NSString *> *)hashes;
- (void)decrementPendingRulesForHash:(NSString *)hash totalRuleCount:(NSNumber *)totalRuleCount;
- (NSDictionary *)all;

@end