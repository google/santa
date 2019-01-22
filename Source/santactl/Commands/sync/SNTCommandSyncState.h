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

@class SNTCommandSyncManager;
@class MOLXPCConnection;

/// An instance of this class is passed to each stage of the sync process for storing data
/// that might be needed in later stages.
@interface SNTCommandSyncState : NSObject

/// Configured session to use for requests.
@property NSURLSession *session;

/// Connection to the daemon control interface.
@property MOLXPCConnection *daemonConn;

/// The base API URL.
@property NSURL *syncBaseURL;

/// An XSRF token to send in the headers with each request.
@property NSString *xsrfToken;

/// An FCM token to subscribe to push notifications.
@property(copy) NSString *FCMToken;

/// Full sync interval in seconds while listening for FCM messages.
@property NSUInteger FCMFullSyncInterval;

/// Leeway time in seconds when receiving a global rule sync message.
@property NSUInteger FCMGlobalRuleSyncDeadline;

/// Machine identifier and owner.
@property(copy) NSString *machineID;
@property(copy) NSString *machineOwner;

/// Settings sent from server during preflight that are set during postflight.
@property SNTClientMode clientMode;
@property NSString *whitelistRegex;
@property NSString *blacklistRegex;

/// Clean sync flag, if True, all existing rules should be deleted before inserting any new rules.
@property BOOL cleanSync;

/// Batch size for uploading events.
@property NSUInteger eventBatchSize;

/// Array of bundle IDs to find binaries for.
@property NSArray *bundleBinaryRequests;

/// Returns YES if the santactl session is running as a daemon, returns NO otherwise.
@property BOOL daemon;

/// Returns YES if the session is targeted for this machine, returns NO otherwise.
@property BOOL targetedRuleSync;

/// Reference to the sync manager's ruleSyncCache. Used to lookup binary names for notifications.
@property(weak) NSMutableDictionary *whitelistNotifications;

/// Reference to the serial operation queue used for accessing whitelistNotifications.
@property(weak) NSOperationQueue *whitelistNotificationQueue;

@end
