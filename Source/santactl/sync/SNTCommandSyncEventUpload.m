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

#import "MOLCertificate.h"
#import "MOLCodesignChecker.h"
#import "NSData+Zlib.h"
#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncState.h"
#import "SNTFileInfo.h"
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

    if (event.fileBundleID) {
      NSArray *relatedBinaries = [self findRelatedBinaries:event];
      [uploadEvents addObjectsFromArray:relatedBinaries];
    }

    if (eventIds.count >= batchSize) break;
  }

  NSDictionary *uploadReq = @{kEvents : uploadEvents};

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

  NSData *compressed = [requestBody zlibCompressed];
  if (compressed) {
    requestBody = compressed;
    [req setValue:@"zlib" forHTTPHeaderField:@"Content-Encoding"];
  }

  [req setHTTPBody:requestBody];

  [[session dataTaskWithRequest:req completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {
    long statusCode = [(NSHTTPURLResponse *)response statusCode];
    if (statusCode != 200) {
      LOGE(@"HTTP Response: %ld %@",
           statusCode,
           [[NSHTTPURLResponse localizedStringForStatusCode:statusCode] capitalizedString]);
      LOGD(@"%@", error);
      handler(NO);
    } else {
      LOGI(@"Uploaded %lu events", eventIds.count);

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
    case SNTEventStateAllowUnknown: ADDKEY(newEvent, kDecision, kDecisionAllowUnknown); break;
    case SNTEventStateAllowBinary: ADDKEY(newEvent, kDecision, kDecisionAllowBinary); break;
    case SNTEventStateAllowCertificate:
      ADDKEY(newEvent, kDecision, kDecisionAllowCertificate);
      break;
    case SNTEventStateAllowScope: ADDKEY(newEvent, kDecision, kDecisionAllowScope); break;
    case SNTEventStateBlockUnknown: ADDKEY(newEvent, kDecision, kDecisionBlockUnknown); break;
    case SNTEventStateBlockBinary: ADDKEY(newEvent, kDecision, kDecisionBlockBinary); break;
    case SNTEventStateBlockCertificate:
      ADDKEY(newEvent, kDecision, kDecisionBlockCertificate);
      break;
    case SNTEventStateBlockScope: ADDKEY(newEvent, kDecision, kDecisionBlockScope); break;
    case SNTEventStateRelatedBinary: ADDKEY(newEvent, kDecision, kDecisionRelatedBinary); break;
    default: ADDKEY(newEvent, kDecision, kDecisionUnknown);
  }

  ADDKEY(newEvent, kFileBundleID, event.fileBundleID);
  ADDKEY(newEvent, kFileBundleName, event.fileBundleName);
  ADDKEY(newEvent, kFileBundleVersion, event.fileBundleVersion);
  ADDKEY(newEvent, kFileBundleShortVersionString, event.fileBundleVersionString);

  ADDKEY(newEvent, kPID, event.pid);
  ADDKEY(newEvent, kPPID, event.ppid);
  ADDKEY(newEvent, kParentName, event.parentName);

  ADDKEY(newEvent, kQuarantineDataURL, event.quarantineDataURL);
  ADDKEY(newEvent, kQuarantineRefererURL, event.quarantineRefererURL);
  ADDKEY(newEvent, kQuarantineTimestamp, @([event.quarantineTimestamp timeIntervalSince1970]));
  ADDKEY(newEvent, kQuarantineAgentBundleID, event.quarantineAgentBundleID);

  NSMutableArray *signingChain = [NSMutableArray arrayWithCapacity:event.signingChain.count];
  for (NSUInteger i = 0; i < event.signingChain.count; ++i) {
    MOLCertificate *cert = [event.signingChain objectAtIndex:i];

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

+ (NSArray *)findRelatedBinaries:(SNTStoredEvent *)event {
  // Prevent processing the same bundle twice.
  static NSMutableDictionary *previouslyProcessedBundles;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    previouslyProcessedBundles = [NSMutableDictionary dictionary];
  });
  if (previouslyProcessedBundles[event.fileBundleID]) return nil;
  previouslyProcessedBundles[event.fileBundleID] = @YES;

  NSMutableArray *relatedEvents = [NSMutableArray array];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block BOOL shouldCancel = NO;
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
    SNTFileInfo *originalFile = [[SNTFileInfo alloc] initWithPath:event.filePath];
    NSString *bundlePath = originalFile.bundlePath;
    originalFile = nil;  // release originalFile early.

    NSDirectoryEnumerator *dirEnum = [[NSFileManager defaultManager] enumeratorAtPath:bundlePath];
    NSString *file;

    while (file = [dirEnum nextObject]) {
      @autoreleasepool {
        if (shouldCancel) break;
        if ([dirEnum fileAttributes][NSFileType] != NSFileTypeRegular) continue;

        file = [bundlePath stringByAppendingPathComponent:file];

        // Don't record the binary that triggered this event as a related binary.
        if ([file isEqual:event.filePath]) continue;

        SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:file];
        if (fi.isExecutable) {
          SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
          se.filePath = fi.path;
          se.fileSHA256 = fi.SHA256;
          se.decision = SNTEventStateRelatedBinary;
          se.fileBundleID = event.fileBundleID;
          se.fileBundleName = event.fileBundleName;
          se.fileBundleVersion = event.fileBundleVersion;
          se.fileBundleVersionString = event.fileBundleVersionString;

          MOLCodesignChecker *cs = [[MOLCodesignChecker alloc] initWithBinaryPath:se.filePath];
          se.signingChain = cs.certificates;

          [relatedEvents addObject:[self dictionaryForEvent:se]];
        }
      }
    }

    dispatch_semaphore_signal(sema);
  });

  // Give the search up to 5s per event to run.
  // This might need tweaking if it seems to slow down syncing or misses too much to be useful.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 5))) {
    shouldCancel = YES;
    LOGD(@"Timed out while searching for related events. Bundle ID: %@", event.fileBundleID);
  }

  return relatedEvents;
}

@end
