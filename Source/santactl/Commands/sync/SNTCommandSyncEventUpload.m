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

- (NSURL *)stageURL {
  NSString *stageName = [@"eventupload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] databaseEventsPending:^(NSArray *events) {
    if (events.count) {
      [self uploadEvents:events];
    }
    dispatch_semaphore_signal(sema);
  }];
  return (dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER) == 0);
}

- (BOOL)syncSingleEventWithSHA256:(NSString *)sha256 {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] databaseEventForSHA256:sha256 reply:^(SNTStoredEvent *e) {
    if (e) {
      [self uploadEvents:@[ e ]];
    }
    dispatch_semaphore_signal(sema);
  }];
  return (dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER) == 0);
}

- (BOOL)syncBundleEvents {
  NSMutableArray *newEvents = [NSMutableArray array];
  for (NSString *bundlePath in self.syncState.bundleBinaryRequests) {
    [newEvents addObjectsFromArray:[self findRelatedBinaries:bundlePath]];
  }
  return [self uploadEvents:newEvents];
}

- (BOOL)uploadEvents:(NSArray *)events {
  NSMutableArray *uploadEvents = [[NSMutableArray alloc] init];

  NSMutableDictionary *eventIds = [NSMutableDictionary dictionaryWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    [uploadEvents addObject:[self dictionaryForEvent:event]];
    if (event.idx) {
      eventIds[event.idx] = @YES;
    }
    if (uploadEvents.count >= self.syncState.eventBatchSize) break;
  }

  NSDictionary *r = [self performRequest:[self requestWithDictionary:@{ kEvents: uploadEvents }]];
  if (!r) return NO;

  // Keep track of bundle search requests
  self.syncState.bundleBinaryRequests = r[kEventUploadBundleBinaries];

  LOGI(@"Uploaded %lu events", uploadEvents.count);

  // Remove event IDs. For Bundle Events the ID is 0 so nothing happens.
  [[self.daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allKeys]];

  // See if there are any events remaining to upload
  if (uploadEvents.count < events.count) {
    NSRange nextEventsRange = NSMakeRange(uploadEvents.count, events.count - uploadEvents.count);
    NSArray *nextEvents = [events subarrayWithRange:nextEventsRange];
    return [self uploadEvents:nextEvents];
  }

  return YES;
}

- (NSDictionary *)dictionaryForEvent:(SNTStoredEvent *)event {
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
    case SNTEventStateBundleBinary: ADDKEY(newEvent, kDecision, kDecisionBundleBinary); break;
    default: ADDKEY(newEvent, kDecision, kDecisionUnknown);
  }

  ADDKEY(newEvent, kFileBundleID, event.fileBundleID);
  ADDKEY(newEvent, kFileBundlePath, event.fileBundlePath);
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

// Find binaries within a bundle given the bundle's path
// Searches for 10 minutes, creating new events.
- (NSArray *)findRelatedBinaries:(NSString *)path {
  SNTFileInfo *requestedPath = [[SNTFileInfo alloc] initWithPath:path];

  // Prevent processing the same bundle twice.
  static NSMutableDictionary *previouslyProcessedBundles;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    previouslyProcessedBundles = [NSMutableDictionary dictionary];
  });
  if (previouslyProcessedBundles[requestedPath.bundleIdentifier]) return nil;
  previouslyProcessedBundles[requestedPath.bundleIdentifier] = @YES;

  NSMutableArray *relatedEvents = [NSMutableArray array];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block BOOL shouldCancel = NO;
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
    NSDirectoryEnumerator *dirEnum = [[NSFileManager defaultManager] enumeratorAtPath:path];
    NSString *file;

    while (file = [dirEnum nextObject]) {
      @autoreleasepool {
        if (shouldCancel) break;
        if ([dirEnum fileAttributes][NSFileType] != NSFileTypeRegular) continue;

        file = [path stringByAppendingPathComponent:file];

        SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:file];
        if (fi.isExecutable) {
          SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
          se.filePath = fi.path;
          se.fileSHA256 = fi.SHA256;
          se.decision = SNTEventStateBundleBinary;
          se.fileBundleID = fi.bundleIdentifier;
          se.fileBundleName = fi.bundleName;
          se.fileBundlePath = fi.bundlePath;
          se.fileBundleVersion = fi.bundleVersion;
          se.fileBundleVersionString = fi.bundleShortVersionString;

          MOLCodesignChecker *cs = [[MOLCodesignChecker alloc] initWithBinaryPath:se.filePath];
          se.signingChain = cs.certificates;

          [relatedEvents addObject:se];
        }
      }
    }

    dispatch_semaphore_signal(sema);
  });

  // Give the search up to 10m per bundle to run.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 600))) {
    shouldCancel = YES;
    LOGD(@"Timed out while searching for related events at path %@", path);
  }

  return relatedEvents;
}

@end
