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

#import "SNTCommandSyncEventUpload.h"

#include "SNTLogging.h"

#import "SNTCertificate.h"
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

+ (void)uploadSingleEventWithSHA256:(NSString *)SHA256
                            session:(NSURLSession *)session
                           progress:(SNTCommandSyncStatus *)progress
                         daemonConn:(SNTXPCConnection *)daemonConn
                  completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[@"eventupload/" stringByAppendingString:progress.machineID]
                      relativeToURL:progress.syncBaseURL];
  [[daemonConn remoteObjectProxy] databaseEventForSHA256:SHA256 withReply:^(SNTStoredEvent *event) {
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
    [uploadEvents addObject:[self dictionaryForEvent:event]];
    [eventIds addObject:event.idx];

    if (eventIds.count >= batchSize) break;
  }

  NSDictionary *uploadReq = @{ @"events": uploadEvents };

  NSData *requestBody;
  @try {
    requestBody = [NSJSONSerialization dataWithJSONObject:uploadReq options:0 error:nil];
  } @catch (NSException *exception) {
    LOGE(@"Failed to parse event(s) into JSON");
    LOGD(@"Parsing error: %@", [exception reason]);
  }

  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPMethod:@"POST"];
  [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
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

+ (NSDictionary *)dictionaryForEvent:(SNTStoredEvent *)event {
#define ADDKEY(dict, key, value) if (value) dict[key] = value
  NSMutableDictionary *newEvent = [NSMutableDictionary dictionary];

  ADDKEY(newEvent, @"file_sha256", event.fileSHA256);
  ADDKEY(newEvent, @"file_path", [event.filePath stringByDeletingLastPathComponent]);
  ADDKEY(newEvent, @"file_name", [event.filePath lastPathComponent]);
  ADDKEY(newEvent, @"executing_user", event.executingUser);
  ADDKEY(newEvent, @"execution_time", @([event.occurrenceDate timeIntervalSince1970]));
  ADDKEY(newEvent, @"decision", @(event.decision));
  ADDKEY(newEvent, @"logged_in_users", event.loggedInUsers);
  ADDKEY(newEvent, @"current_sessions", event.currentSessions);

  ADDKEY(newEvent, @"file_bundle_id", event.fileBundleID);
  ADDKEY(newEvent, @"file_bundle_name", event.fileBundleName);
  ADDKEY(newEvent, @"file_bundle_version", event.fileBundleVersion);
  ADDKEY(newEvent, @"file_bundle_version_string", event.fileBundleVersionString);

  ADDKEY(newEvent, @"pid", event.pid);
  ADDKEY(newEvent, @"ppid", event.ppid);

  NSMutableArray *signingChain = [NSMutableArray arrayWithCapacity:event.signingChain.count];
  for (int i = 0; i < event.signingChain.count; i++) {
    SNTCertificate *cert = [event.signingChain objectAtIndex:i];

    NSMutableDictionary *certDict = [NSMutableDictionary dictionary];
    ADDKEY(certDict, @"sha256", cert.SHA256);
    ADDKEY(certDict, @"cn", cert.commonName);
    ADDKEY(certDict, @"org", cert.orgName);
    ADDKEY(certDict, @"ou", cert.orgUnit);
    ADDKEY(certDict, @"valid_from", @([cert.validFrom timeIntervalSince1970]));
    ADDKEY(certDict, @"valid_until", @([cert.validUntil timeIntervalSince1970]));

    [signingChain addObject:certDict];
  }
  newEvent[@"signing_chain"] = signingChain;

  return newEvent;
#undef ADDKEY
}

@end
