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

#import "Source/santasyncservice/SNTPushNotificationsTracker.h"

#import "Source/common/SNTLogging.h"
#import "Source/santasyncservice/SNTSyncConstants.h"

@interface SNTPushNotificationsTracker ()

@property dispatch_queue_t notificationsQueue;
@property NSMutableDictionary *notifications;
@end

@implementation SNTPushNotificationsTracker

- (instancetype)init {
  self = [super init];
  if (self) {
    _notifications = [NSMutableDictionary dictionary];
    _notificationsQueue =
      dispatch_queue_create("com.google.santa.syncservice.notifications", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

+ (instancetype)tracker {
  static SNTPushNotificationsTracker *tracker;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    tracker = [[SNTPushNotificationsTracker alloc] init];
  });
  return tracker;
}

- (void)addNotification:(NSDictionary *)notification forHash:(NSString *)hash {
  dispatch_async(self.notificationsQueue, ^() {
    // Don't let notifications pile up. In most cases there will only be a single entry pending. It
    // is possible for notifications to make it here but not be displayed. The TODO below is to
    // address this.
    // TODO(bur): Add better guaranties for displaying notifications. This will involve checking the
    // rules.db to see if the rule associated with the notification has been applied.
    if (self.notifications.count > 16) {
      LOGE(@"Push notifications are not being processed. Dropping pending notifications.");
      [self.notifications removeAllObjects];
    }
    self.notifications[hash] = notification;
  });
}

- (void)removeNotificationsForHashes:(NSArray<NSString *> *)hashes {
  dispatch_async(self.notificationsQueue, ^() {
    [self.notifications removeObjectsForKeys:hashes];
  });
}

- (void)decrementPendingRulesForHash:(NSString *)hash totalRuleCount:(NSNumber *)totalRuleCount {
  dispatch_async(self.notificationsQueue, ^() {
    NSMutableDictionary *notifier = self.notifications[hash];
    if (notifier) {
      NSNumber *remaining = notifier[kFileBundleBinaryCount];
      if (remaining) {  // bundle rule with existing count
        // If the primary hash already has an associated count field, just decrement it.
        notifier[kFileBundleBinaryCount] = @([remaining intValue] - 1);
      } else if (totalRuleCount) {  // bundle rule seen for first time
        // Downloaded rules including count information are associated with bundles.
        // The first time we see a rule for a given bundle hash, add a count field with an
        // initial value equal to the number of associated rules, then decrement this value by 1
        // to account for the rule that we've just downloaded.
        notifier[kFileBundleBinaryCount] = @([totalRuleCount intValue] - 1);
      } else {  // non-bundle binary rule
        // Downloaded rule had no count information, meaning it is a singleton non-bundle rule.
        // Therefore there are no more rules associated with this hash to download.
        notifier[kFileBundleBinaryCount] = @0;
      }
    }
  });
}

- (NSDictionary *)all {
  __block NSDictionary *d;
  dispatch_sync(self.notificationsQueue, ^() {
    d = self.notifications;
  });
  return d;
}

@end
