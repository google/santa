/// Copyright 2014 Google Inc. All rights reserved.
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

#import "SNTCommandSyncEventUpload.h"

#include "SNTLogging.h"

#import "SNTCommandSyncStatus.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@implementation SNTCommandSyncEventUpload

+ (void)performSyncInSession:(NSURLSession *)session
                    progress:(SNTCommandSyncStatus *)progress
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[@"eventupload/" stringByAppendingString:progress.machineID]
                      relativeToURL:progress.syncBaseURL];

  [[daemonConn remoteObjectProxy] databaseEventsPending:^(NSArray *events) {
      if ([events count] == 0) {
        handler(YES);
      } else {
        [self uploadEventsFromArray:events
                              toURL:url
                          inSession:session
                          batchSize:progress.eventBatchSize
                         daemonConn:daemonConn
                  completionHandler:handler];
      }
  }];
}

+ (void)uploadSingleEventWithSHA1:(NSString *)SHA1
                          session:(NSURLSession *)session
                         progress:(SNTCommandSyncStatus *)progress
                       daemonConn:(SNTXPCConnection *)daemonConn
                completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[@"eventupload/" stringByAppendingString:progress.machineID]
                      relativeToURL:progress.syncBaseURL];
  [[daemonConn remoteObjectProxy] databaseEventForSHA1:SHA1 withReply:^(SNTStoredEvent *event) {
      if (!event) {
        handler(YES);
        return;
      }

      [self uploadEventsFromArray:@[ event ]
                            toURL:url
                        inSession:session
                        batchSize:1
                       daemonConn:daemonConn
                completionHandler:handler];
  }];
}

+ (void)uploadEventsFromArray:(NSArray *)events
                        toURL:(NSURL *)url
                    inSession:(NSURLSession *)session
                    batchSize:(int32_t)batchSize
                   daemonConn:(SNTXPCConnection *)daemonConn
            completionHandler:(void (^)(BOOL success))handler {
  NSMutableArray *uploadEvents = [[NSMutableArray alloc] init];

  NSMutableArray *eventIds = [NSMutableArray arrayWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    NSMutableDictionary *newEvent = [@{
        @"file_sha1": event.fileSHA1,
        @"file_path": [event.filePath stringByDeletingLastPathComponent],
        @"file_name": [event.filePath lastPathComponent],
        @"executing_user": event.executingUser,
        @"execution_time": @([event.occurrenceDate timeIntervalSince1970]),
        @"decision": @(event.decision),
        @"logged_in_users": event.loggedInUsers,
        @"current_sessions": event.currentSessions} mutableCopy];


    if (event.fileBundleID) newEvent[@"file_bundle_id"] = event.fileBundleID;
    if (event.fileBundleName) newEvent[@"file_bundle_name"] = event.fileBundleName;
    if (event.fileBundleVersion) newEvent[@"file_bundle_version"] = event.fileBundleVersion;
    if (event.fileBundleVersionString) {
      newEvent[@"file_bundle_version_string"] = event.fileBundleVersionString;
    }

    if (event.certSHA1) newEvent[@"cert_sha1"] = event.certSHA1;
    if (event.certCN) newEvent[@"cert_cn"] = event.certCN;
    if (event.certOrg) newEvent[@"cert_org"] = event.certOrg;
    if (event.certOU) newEvent[@"cert_ou"] = event.certOU;
    if (event.certValidFromDate) {
      newEvent[@"cert_valid_from"] = @([event.certValidFromDate timeIntervalSince1970]);
    }
    if (event.certValidUntilDate) {
      newEvent[@"cert_valid_until"] = @([event.certValidUntilDate timeIntervalSince1970]);
    }

    [uploadEvents addObject:newEvent];

    [eventIds addObject:event.idx];

    if (eventIds.count >= batchSize) break;
  }

  NSDictionary *uploadReq = @{@"events": uploadEvents};

  NSData *requestBody;
  @try {
    requestBody = [NSJSONSerialization dataWithJSONObject:uploadReq options:0 error:nil];
  } @catch (NSException *exception) {
    LOGE(@"Failed to parse event into JSON");
  }

  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPMethod:@"POST"];
  [req setHTTPBody:requestBody];

  [[session dataTaskWithRequest:req completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {
      if ([(NSHTTPURLResponse *)response statusCode] != 200) {
        LOGD(@"HTTP Response Code: %d", [(NSHTTPURLResponse *)response statusCode]);
        handler(NO);
      } else {
        LOGI(@"Uploaded %d events", eventIds.count);

        [[daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:eventIds];

        NSArray *nextEvents = [events subarrayWithRange:NSMakeRange(eventIds.count,
                                                                    events.count - eventIds.count)];

        if (nextEvents.count == 0) {
          handler(YES);
        } else {
          [self uploadEventsFromArray:nextEvents
                                toURL:url
                            inSession:session
                            batchSize:batchSize
                           daemonConn:daemonConn
                    completionHandler:handler];
        }
      }
  }] resume];
}

@end
