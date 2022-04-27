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

@protocol SNTPushNotificationsDelegate
- (void)sync;
- (void)syncSecondsFromNow:(uint64_t)seconds;
- (void)ruleSync;
- (void)ruleSyncSecondsFromNow:(uint64_t)seconds;
- (void)preflightSync;
@end

@class SNTSyncState;
@class SNTSyncFCM;

@interface SNTPushNotifications : NSObject

- (void)listenWithSyncState:(SNTSyncState *)syncState;
- (void)stop;
@property(weak) id<SNTPushNotificationsDelegate> delegate;
@property(readonly) BOOL isConnected;
@property(readonly) NSString *token;
@property(readonly) NSUInteger pushNotificationsFullSyncInterval;

@end
