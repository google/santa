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
  for (NSString *bundlePath in [NSSet setWithArray:self.syncState.bundleBinaryRequests]) {
    __block NSArray *relatedBinaries;
    __block BOOL shouldCancel = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
      relatedBinaries = [self findRelatedBinaries:bundlePath shouldCancel:&shouldCancel];
      dispatch_semaphore_signal(sema);
    });

    // Give the search up to 5m to run
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 300))) {
      LOGD(@"Timed out while searching for related binaries at path %@", bundlePath);
      shouldCancel = YES;
    } else {
      [newEvents addObjectsFromArray:relatedBinaries];
    }
  }
  return [self uploadEvents:newEvents];
}

- (BOOL)uploadEvents:(NSArray *)events {
  NSMutableArray *uploadEvents = [[NSMutableArray alloc] init];

  NSMutableSet *eventIds = [NSMutableSet setWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    [uploadEvents addObject:[self dictionaryForEvent:event]];
    if (event.idx) [eventIds addObject:event.idx];
    if (uploadEvents.count >= self.syncState.eventBatchSize) break;
  }

  NSDictionary *r = [self performRequest:[self requestWithDictionary:@{ kEvents: uploadEvents }]];
  if (!r) return NO;

  // Keep track of bundle search requests
  self.syncState.bundleBinaryRequests = r[kEventUploadBundleBinaries];

  LOGI(@"Uploaded %lu events", uploadEvents.count);

  // Remove event IDs. For Bundle Events the ID is 0 so nothing happens.
  [[self.daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allObjects]];

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

/**
  Find binaries within a bundle given the bundle's path. Will run until completion, however long
  that might be. Search is done within the bundle concurrently, using up to 25 threads at once.

  @param path, the path to begin searching underneath
  @param shouldCancel, if YES, the search is cancelled part way through.
  @return array of SNTStoredEvent's
*/
- (NSArray *)findRelatedBinaries:(NSString *)path shouldCancel:(BOOL *)shouldCancel {
  // For storing the generated events, with a simple lock for writing.
  NSMutableArray *relatedEvents = [NSMutableArray array];
  NSLock *relatedEventsLock = [[NSLock alloc] init];

  // Limit the number of threads that can process files at once to keep CPU usage down.
  dispatch_semaphore_t sema = dispatch_semaphore_create(25);

  // Group the processing into a single group so we can wait on the whole group at the end.
  dispatch_group_t group = dispatch_group_create();

  NSDirectoryEnumerator *dirEnum = [[NSFileManager defaultManager] enumeratorAtPath:path];
  while (1) {
    @autoreleasepool {
      if (*shouldCancel) break;
      NSString *file = [dirEnum nextObject];
      if (!file) break;
      if ([dirEnum fileAttributes][NSFileType] != NSFileTypeRegular) continue;

      // Wait for a processing thread to become available
      dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

      dispatch_group_async(group,
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0),
                           ^{
        @autoreleasepool {
          NSString *newFile = [path stringByAppendingPathComponent:file];
          SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:newFile];
          if (!fi.isExecutable) {
            dispatch_semaphore_signal(sema);
            return;
          }

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

          [relatedEventsLock lock];
          [relatedEvents addObject:se];
          [relatedEventsLock unlock];

          dispatch_semaphore_signal(sema);
        }
      });
    }
  }

  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);

  return relatedEvents;
}

@end
