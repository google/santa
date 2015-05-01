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
#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncState.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@implementation SNTCommandSyncEventUpload

+ (void)performSyncInSession:(NSURLSession *)session
                   syncState:(SNTCommandSyncState *)syncState
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[kURLEventUpload stringByAppendingString:syncState.machineID]
                      relativeToURL:syncState.syncBaseURL];

  [[daemonConn remoteObjectProxy] databaseEventsPending:^(NSArray *events) {
      if ([events count] == 0) {
        handler(YES);
      } else {
        [self uploadEventsFromArray:events
                              toURL:url
                          inSession:session
                          batchSize:syncState.eventBatchSize
                         daemonConn:daemonConn
                  completionHandler:handler];
      }
  }];
}

+ (void)uploadSingleEventWithSHA256:(NSString *)SHA256
                            session:(NSURLSession *)session
                          syncState:(SNTCommandSyncState *)syncState
                         daemonConn:(SNTXPCConnection *)daemonConn
                  completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[kURLEventUpload stringByAppendingString:syncState.machineID]
                      relativeToURL:syncState.syncBaseURL];
  [[daemonConn remoteObjectProxy] databaseEventForSHA256:SHA256 reply:^(SNTStoredEvent *event) {
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
                    batchSize:(NSUInteger)batchSize
                   daemonConn:(SNTXPCConnection *)daemonConn
            completionHandler:(void (^)(BOOL success))handler {
  NSMutableArray *uploadEvents = [[NSMutableArray alloc] init];

  NSMutableArray *eventIds = [NSMutableArray arrayWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    [uploadEvents addObject:[self dictionaryForEvent:event]];
    [eventIds addObject:event.idx];

    if (eventIds.count >= batchSize) break;
  }

  NSDictionary *uploadReq = @{ kEvents: uploadEvents };

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
      long statusCode = [(NSHTTPURLResponse *)response statusCode];
      if (statusCode != 200) {
          LOGE(@"HTTP Response: %d %@",
               statusCode,
               [[NSHTTPURLResponse localizedStringForStatusCode:statusCode] capitalizedString]);
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

  ADDKEY(newEvent, kFileSHA256, event.fileSHA256);
  ADDKEY(newEvent, kFilePath, [event.filePath stringByDeletingLastPathComponent]);
  ADDKEY(newEvent, kFileName, [event.filePath lastPathComponent]);
  ADDKEY(newEvent, kExecutingUser, event.executingUser);
  ADDKEY(newEvent, kExecutionTime, @([event.occurrenceDate timeIntervalSince1970]));
  ADDKEY(newEvent, kLoggedInUsers, event.loggedInUsers);
  ADDKEY(newEvent, kCurrentSessions, event.currentSessions);

  switch (event.decision) {
    case EVENTSTATE_ALLOW_UNKNOWN: ADDKEY(newEvent, kDecision, kDecisionAllowUnknown); break;
    case EVENTSTATE_ALLOW_BINARY: ADDKEY(newEvent, kDecision, kDecisionAllowBinary); break;
    case EVENTSTATE_ALLOW_CERTIFICATE:
      ADDKEY(newEvent, kDecision, kDecisionAllowCertificate);
      break;
    case EVENTSTATE_ALLOW_SCOPE: ADDKEY(newEvent, kDecision, kDecisionAllowScope); break;
    case EVENTSTATE_BLOCK_UNKNOWN: ADDKEY(newEvent, kDecision, kDecisionBlockUnknown); break;
    case EVENTSTATE_BLOCK_BINARY: ADDKEY(newEvent, kDecision, kDecisionBlockBinary); break;
    case EVENTSTATE_BLOCK_CERTIFICATE:
      ADDKEY(newEvent, kDecision, kDecisionBlockCertificate);
      break;
    case EVENTSTATE_BLOCK_SCOPE: ADDKEY(newEvent, kDecision, kDecisionBlockScope); break;
    default: ADDKEY(newEvent, kDecision, kDecisionUnknown);
  }

  ADDKEY(newEvent, kFileBundleID, event.fileBundleID);
  ADDKEY(newEvent, kFileBundleName, event.fileBundleName);
  ADDKEY(newEvent, kFileBundleVersion, event.fileBundleVersion);
  ADDKEY(newEvent, kFileBundleShortVersionString, event.fileBundleVersionString);

  ADDKEY(newEvent, kPID, event.pid);
  ADDKEY(newEvent, kPPID, event.ppid);
  ADDKEY(newEvent, kParentName, event.parentName);

  NSMutableArray *signingChain = [NSMutableArray arrayWithCapacity:event.signingChain.count];
  for (NSUInteger i = 0; i < event.signingChain.count; i++) {
    SNTCertificate *cert = [event.signingChain objectAtIndex:i];

    NSMutableDictionary *certDict = [NSMutableDictionary dictionary];
    ADDKEY(certDict, kCertSHA256, cert.SHA256);
    ADDKEY(certDict, kCertCN, cert.commonName);
    ADDKEY(certDict, kCertOrg, cert.orgName);
    ADDKEY(certDict, kCertOU, cert.orgUnit);
    ADDKEY(certDict, kCertValidFrom, @([cert.validFrom timeIntervalSince1970]));
    ADDKEY(certDict, kCertValidUntil, @([cert.validUntil timeIntervalSince1970]));

    [signingChain addObject:certDict];
  }
  newEvent[kSigningChain] = signingChain;

  return newEvent;
#undef ADDKEY
}

@end
