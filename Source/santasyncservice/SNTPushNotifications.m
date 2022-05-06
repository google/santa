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

#import "Source/santasyncservice/SNTPushNotifications.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/santasyncservice/SNTPushNotificationsTracker.h"
#import "Source/santasyncservice/SNTSyncConstants.h"
#import "Source/santasyncservice/SNTSyncFCM.h"
#import "Source/santasyncservice/SNTSyncState.h"

static NSString *const kFCMActionKey = @"action";
static NSString *const kFCMFileHashKey = @"file_hash";
static NSString *const kFCMFileNameKey = @"file_name";
static NSString *const kFCMTargetHostIDKey = @"target_host_id";

@interface SNTPushNotifications ()

@property SNTSyncFCM *FCMClient;
@property NSString *token;

@property NSUInteger pushNotificationsFullSyncInterval;
@property NSUInteger pushNotificationsGlobalRuleSyncDeadline;

@end

@implementation SNTPushNotifications

#pragma mark push notification methods

- (instancetype)init {
  self = [super init];
  if (self) {
    _pushNotificationsFullSyncInterval = kDefaultPushNotificationsFullSyncInterval;
    _pushNotificationsGlobalRuleSyncDeadline = kDefaultPushNotificationsGlobalRuleSyncDeadline;
  }
  return self;
}

- (void)listenWithSyncState:(SNTSyncState *)syncState {
  self.pushNotificationsFullSyncInterval = syncState.pushNotificationsFullSyncInterval;
  self.pushNotificationsGlobalRuleSyncDeadline = syncState.pushNotificationsGlobalRuleSyncDeadline;

  if ([self.token isEqualToString:syncState.pushNotificationsToken]) {
    LOGD(@"Already listening for push notifications");
    return;
  }
  LOGD(@"Start listening for push notifications");

  WEAKIFY(self);

  [self.FCMClient disconnect];
  NSString *machineID = syncState.machineID;
  SNTConfigurator *config = [SNTConfigurator configurator];
  self.FCMClient = [[SNTSyncFCM alloc] initWithProject:config.fcmProject
                                                entity:config.fcmEntity
                                                apiKey:config.fcmAPIKey
                                  sessionConfiguration:syncState.session.configuration.copy
                                        messageHandler:^(NSDictionary *message) {
                                          if (!message || message[@"noOp"]) return;
                                          STRONGIFY(self);
                                          LOGD(@"%@", message);
                                          [self.FCMClient acknowledgeMessage:message];
                                          [self processFCMMessage:message withMachineID:machineID];
                                        }];

  self.FCMClient.tokenHandler = ^(NSString *t) {
    STRONGIFY(self);
    LOGD(@"tokenHandler: %@", t);
    self.token = t;
    [self.delegate preflightSync];
  };

  self.FCMClient.connectionErrorHandler = ^(NSHTTPURLResponse *response, NSError *error) {
    STRONGIFY(self);
    if (response) LOGE(@"FCM fatal response: %@", response);
    if (error) LOGE(@"FCM fatal error: %@", error);
    [self.FCMClient disconnect];
    self.FCMClient = nil;
    self.token = nil;
    [self.delegate syncSecondsFromNow:kDefaultFullSyncInterval];
  };

  [self.FCMClient connect];
}

- (void)stop {
  [self.FCMClient disconnect];
  self.FCMClient = nil;
}

- (void)processFCMMessage:(NSDictionary *)FCMmessage withMachineID:(NSString *)machineID {
  NSDictionary *message = [self messageFromMessageData:[self messageDataFromFCMmessage:FCMmessage]];

  if (!message) {
    LOGD(@"Push notification message is not in the expected format...dropping message");
    return;
  }

  NSString *action = message[kFCMActionKey];
  if (!action) {
    LOGD(@"Push notification message contains no action");
    return;
  }

  // We assume that the incoming FCM message contains name of binary/bundle and a hash.  Rule count
  // info for bundles will be sent out later with the rules themselves.  If the message is related
  // to a bundle, the hash is a bundle hash, otherwise it is just a hash for a single binary.
  // For later use, we store a mapping of bundle/binary hash to a dictionary containing the
  // binary/bundle name so we can send out relevant notifications once the rules are actually
  // downloaded & added to local database.  We use a dictionary value so that we can later add a
  // count field when we start downloading the rules and receive the count information.
  NSString *fileHash = message[kFCMFileHashKey];
  NSString *fileName = message[kFCMFileNameKey];
  if (fileName && fileHash) {
    [[SNTPushNotificationsTracker tracker] addNotification:[@{kFileName : fileName} mutableCopy]
                                                   forHash:fileHash];
  }

  LOGD(@"Push notification action '%@' received", action);

  if ([action isEqualToString:kFullSync] || [action isEqualToString:kConfigSync] ||
      [action isEqualToString:kLogSync]) {
    [self.delegate sync];
  } else if ([action isEqualToString:kRuleSync]) {
    NSString *targetHostID = message[kFCMTargetHostIDKey];
    if (targetHostID && [targetHostID caseInsensitiveCompare:machineID] == NSOrderedSame) {
      LOGD(@"Targeted rule_sync for host_id: %@", targetHostID);
      [self.delegate ruleSync];
    } else {
      uint32_t delaySeconds =
        arc4random_uniform((uint32_t)self.pushNotificationsGlobalRuleSyncDeadline);
      LOGD(@"Global rule_sync, staggering: %u second delay", delaySeconds);
      [self.delegate ruleSyncSecondsFromNow:delaySeconds];
    }
  } else {
    LOGD(@"Unrecognised action: %@", action);
  }
}

- (NSData *)messageDataFromFCMmessage:(NSDictionary *)FCMmessage {
  if (![FCMmessage[@"data"] isKindOfClass:[NSDictionary class]]) return nil;
  if (![FCMmessage[@"data"][@"blob"] isKindOfClass:[NSString class]]) return nil;
  return [FCMmessage[@"data"][@"blob"] dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSDictionary *)messageFromMessageData:(NSData *)messageData {
  if (!messageData) {
    LOGD(@"Unable to parse push notification message data");
    return nil;
  }
  NSError *error;
  NSDictionary *rawMessage = [NSJSONSerialization JSONObjectWithData:messageData
                                                             options:0
                                                               error:&error];
  if (!rawMessage) {
    LOGD(@"Unable to parse push notification message data: %@", error);
    return nil;
  }

  // Create a new message dropping unexpected values
  NSArray *allowedKeys = @[ kFCMActionKey, kFCMFileHashKey, kFCMFileNameKey, kFCMTargetHostIDKey ];
  NSMutableDictionary *message = [NSMutableDictionary dictionaryWithCapacity:allowedKeys.count];
  for (NSString *key in allowedKeys) {
    if ([rawMessage[key] isKindOfClass:[NSString class]] && [rawMessage[key] length]) {
      message[key] = rawMessage[key];
    }
  }
  return message.count ? [message copy] : nil;
}

- (BOOL)isConnected {
  return self.FCMClient.isConnected;
}

@end