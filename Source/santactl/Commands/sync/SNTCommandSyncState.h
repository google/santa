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

#import "SNTCommonEnums.h"

@class SNTXPCConnection;

/// An instance of this class is passed to each stage of the sync process for storing data
/// that might be needed in later stages.
@interface SNTCommandSyncState : NSObject

/// Configured session to use for requests.
@property NSURLSession *session;

/// Connection to the daemon control interface.
@property SNTXPCConnection *daemonConn;

/// The base API URL.
@property NSURL *syncBaseURL;

/// An XSRF token to send in the headers with each request.
@property NSString *xsrfToken;

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

/// Log upload URL sent from server. If set, LogUpload phase needs to happen.
@property NSURL *uploadLogURL;

/// Array of bundle paths to find binaries for.
@property NSArray *bundleBinaryRequests;

/// Rules downloaded from server.
@property NSMutableArray *downloadedRules;

@end
