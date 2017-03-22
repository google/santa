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

@import Foundation;

#import "SNTCommonEnums.h"
#import "SNTXPCBundleServiceInterface.h"

@class SNTStoredEvent;

/// Protocol implemented by SantaGUI and utilized by santad
@protocol SNTNotifierXPC
- (void)postBlockNotification:(SNTStoredEvent *)event withCustomMessage:(NSString *)message;
- (void)postClientModeNotification:(SNTClientMode)clientmode;
- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message;
@end

/// Protocol implemented by SantaGUI and utilized by santabs
@protocol SNTBundleNotifierXPC
- (void)updateCountsForEvent:(SNTStoredEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount;
- (void)setBundleServiceListener:(NSXPCListenerEndpoint *)listener;
@end

@interface SNTXPCNotifierInterface : NSObject

///
///  @return an initialized NSXPCInterface for the SNTNotifierXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)notifierInterface;

///
///  @return an initialized NSXPCInterface for the SNTBundleNotifierXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)bundleNotifierInterface;

@end
