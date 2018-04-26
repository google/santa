/// Copyright 2016 Google Inc. All rights reserved.
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

#import "SNTCommonEnums.h"

@class SNTStoredEvent;

/// Protocol implemented by santactl and utilized by santad
@protocol SNTSyncdXPC
- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events isFromBundle:(BOOL)isFromBundle;
- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply;
- (void)isFCMListening:(void (^)(BOOL))reply;
@end

@interface SNTXPCSyncdInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTSyncdXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)syncdInterface;

@end
