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

/// An instance of this class is passed to each stage of the sync process for storing data
/// that might be needed in later stages.
@interface SNTCommandSyncState : NSObject

/// The base API URL
@property NSURL *syncBaseURL;

/// Machine identifier and owner
@property(copy) NSString *machineID;
@property(copy) NSString *machineOwner;

/// Clean sync flag, sent from server. If True, all existing rules
/// should be deleted before inserting any new rules.
@property BOOL cleanSync;

/// New client mode sent from server
@property SNTClientMode newClientMode;

/// Batch size for uploading events, sent from server
@property int32_t eventBatchSize;

/// Log upload URL sent from server
@property NSURL *uploadLogURL;

/// Rules downloaded from server
@property NSMutableArray *downloadedRules;

@end
