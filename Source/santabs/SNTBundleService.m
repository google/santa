/// Copyright 2017 Google Inc. All rights reserved.
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

#import "SNTBundleService.h"

#import <CommonCrypto/CommonDigest.h>
#import <pthread/pthread.h>

#import "MOLCertificate.h"
#import "MOLCodesignChecker.h"
#import "SNTFileInfo.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCNotifierInterface.h"

@interface SNTBundleService ()
@property SNTXPCConnection *notifierConnection;
@property SNTXPCConnection *listener;
@end

@implementation SNTBundleService

#pragma mark Connection handling

// Create a listener for SantaGUI to connect
- (void)createConnection {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Create listener for return connection from SantaGUI.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.listener = [[SNTXPCConnection alloc] initServerWithListener:listener];
  self.listener.exportedInterface = [SNTXPCBundleServiceInterface bundleServiceInterface];
  self.listener.exportedObject = self;
  self.listener.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };

  // Exit when SantaGUI is done with us.
  self.listener.invalidationHandler = ^{
    exit(0);
  };

  [self.listener resume];

  // Tell SantaGUI to connect back to the above listener.
  [[self.notifierConnection remoteObjectProxy] setBundleServiceListener:listener.endpoint];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self attemptReconnection];
  }
}

- (void)attemptReconnection {
  [self performSelectorInBackground:@selector(createConnection) withObject:nil];
}


#pragma mark SNTBundleServiceXPC Methods

// Connect to the SantaGUI
- (void)setBundleNotificationListener:(NSXPCListenerEndpoint *)listener {
  SNTXPCConnection *c = [[SNTXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCNotifierInterface bundleNotifierInterface];
  [c resume];
  self.notifierConnection = c;
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
    [self createConnection];
  });
}

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                             reply:(SNTBundleHashBlock)reply {
  NSProgress *progress =
      [NSProgress currentProgress] ? [NSProgress progressWithTotalUnitCount:1] : nil;

  NSDate *startTime = [NSDate date];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
    // Use the highest bundle we can find. Save and reuse the bundle infomation when creating
    // the related binary events.
    SNTFileInfo *b = [[SNTFileInfo alloc] initWithPath:event.fileBundlePath];
    b.useAncestorBundle = YES;
    event.fileBundlePath = b.bundlePath;
    event.fileBundleID = b.bundleIdentifier;
    event.fileBundleName = b.bundleName;
    event.fileBundleVersion = b.bundleVersion;
    event.fileBundleVersionString = b.bundleShortVersionString;

    NSArray *relatedBinaries = [self findRelatedBinaries:event progress:progress];
    NSString *bundleHash = [self calculateBundleHashFromEvents:relatedBinaries];
    NSNumber *ms = [NSNumber numberWithDouble:[startTime timeIntervalSinceNow] * -1000.0];
    if (bundleHash) LOGD(@"hashed %@ in %@ ms", event.fileBundlePath, ms);
    reply(bundleHash, relatedBinaries, ms);
    dispatch_semaphore_signal(sema);
  });

  // Master timeout of 10 min. Don't block the calling thread. NSProgress updates will be coming
  // in over this thread.
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC))) {
      LOGD(@"hashBundleBinariesForEvent timeout");
      [progress cancel];
    }
  });
}

#pragma mark Internal Methods

/**
 Find binaries within a bundle given the bundle's event. It will run until a timeout occurs, 
 or until the NSProgress is cancelled. Search is done within the bundle concurrently.

 @param event The SNTStoredEvent to begin searching underneath
 @return An array of SNTStoredEvent's

 @note The first stage gathers a set of executables. 60 sec / max thread timeout.
 @note The second stage hashes the executables. 300 sec / max thread timeout.
 */
- (NSArray *)findRelatedBinaries:(SNTStoredEvent *)event progress:(NSProgress *)progress {
  // For storing the generated events, with a simple lock for writing.
  NSMutableArray *relatedEvents = [NSMutableArray array];

  // For storing files to be hashed
  NSMutableSet<SNTFileInfo *> *fis = [NSMutableSet set];

  // Limit the number of threads that can process files at once to keep CPU usage down.
  dispatch_semaphore_t sema =
      dispatch_semaphore_create([[NSProcessInfo processInfo] processorCount] / 2);

  // Group the processing into a single group so we can wait on the whole group after each stage.
  dispatch_group_t group = dispatch_group_create();

  // Directory enumerator
  NSDirectoryEnumerator *dirEnum =
      [[NSFileManager defaultManager] enumeratorAtPath:event.fileBundlePath];

  // Locks for accessing the enumerator and adding file and events between threads.
  __block pthread_mutex_t enumeratorMutex = PTHREAD_MUTEX_INITIALIZER;
  __block pthread_mutex_t eventsMutex = PTHREAD_MUTEX_INITIALIZER;

  // Counts used as additional progress information in SantaGUI
  __block uint64_t binaryCount = 0;
  __block uint64_t sentBinaryCount = 0;
  __block uint64_t fileCount = 0;

  __block BOOL breakDir = NO;

  // In the first stage iterate over every file in the tree checking if it is a binary. If so add
  // it to the fis set for the second stage. Hashing the file while iterating over the filesystem
  // causes performance issues. Do them separately.
  while (1) {
    @autoreleasepool {
      if (breakDir || progress.isCancelled) break;

      // Wait for a processing thread to become available. At this stage we are only reading the
      // mach_header. If all processing threads are blocking for more than 60 sec bail.
      if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC))) {
        LOGD(@"isExecutable processing threads timeout");
        return nil;
      }

      dispatch_group_async(group,
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        pthread_mutex_lock(&enumeratorMutex);
        NSString *file = [dirEnum nextObject];
        fileCount++;
        pthread_mutex_unlock(&enumeratorMutex);

        if (!file) {
          breakDir = YES;
          dispatch_semaphore_signal(sema);
          return;
        }

        if ([dirEnum fileAttributes][NSFileType] != NSFileTypeRegular) {
          dispatch_semaphore_signal(sema);
          return;
        }

        NSString *newFile = [event.fileBundlePath stringByAppendingPathComponent:file];
        SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:newFile];
        if (!fi.isExecutable) {
          dispatch_semaphore_signal(sema);
          return;
        }

        pthread_mutex_lock(&eventsMutex);
        [fis addObject:fi];
        binaryCount++;
        pthread_mutex_unlock(&eventsMutex);

        dispatch_semaphore_signal(sema);
      });
      if (progress && ((fileCount % 500) == 0 || binaryCount > sentBinaryCount)) {
        sentBinaryCount = binaryCount;
        [[self.notifierConnection remoteObjectProxy] updateCountsForEvent:event
                                                              binaryCount:binaryCount
                                                                fileCount:fileCount];
      }
    }
  }

  if (progress.isCancelled) return nil;

  // Wait for all the processing threads to finish
  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);

  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:1];
    p = [NSProgress progressWithTotalUnitCount:fis.count];
  }

  // In the second stage perform SHA256 hashing on all of the found binaries.
  for (SNTFileInfo *fi in fis) {
    @autoreleasepool {
      if (progress.isCancelled) break;

      // Wait for a processing thread to become available. Here we are hashing the entire file.
      // If all processing threads are blocking for more than 5 min bail.
      if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_SEC))) {
        LOGD(@"SHA256 processing threads timeout");
        return nil;
      }

      dispatch_group_async(group,
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @autoreleasepool {
          SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
          se.filePath = fi.path;
          se.fileSHA256 = fi.SHA256;
          se.occurrenceDate = [NSDate distantFuture];
          se.decision = SNTEventStateBundleBinary;

          se.fileBundlePath = event.fileBundlePath;
          se.fileBundleID = event.fileBundleID;
          se.fileBundleName = event.fileBundleName;
          se.fileBundleVersion = event.fileBundleVersion;
          se.fileBundleVersionString = event.fileBundleVersionString;

          MOLCodesignChecker *cs = [[MOLCodesignChecker alloc] initWithBinaryPath:se.filePath];
          se.signingChain = cs.certificates;

          pthread_mutex_lock(&eventsMutex);
          [relatedEvents addObject:se];
          p.completedUnitCount++;
          pthread_mutex_unlock(&eventsMutex);

          dispatch_semaphore_signal(sema);
        }
      });
    }
  }

  // Wait for all the processing threads to finish
  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);

  pthread_mutex_destroy(&enumeratorMutex);
  pthread_mutex_destroy(&eventsMutex);

  return progress.isCancelled ? nil : relatedEvents;
}

- (NSString *)calculateBundleHashFromEvents:(NSArray<SNTStoredEvent *> *)events {
  if (!events) return nil;
  NSMutableArray *eventSHA256Hashes = [NSMutableArray arrayWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    if (!event.fileSHA256) return nil;
    [eventSHA256Hashes addObject:event.fileSHA256];
  }

  [eventSHA256Hashes sortUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
  NSString *sha256Hashes = [eventSHA256Hashes componentsJoinedByString:@""];

  CC_SHA256_CTX c256;
  CC_SHA256_Init(&c256);
  CC_SHA256_Update(&c256, (const void *)sha256Hashes.UTF8String, (CC_LONG)sha256Hashes.length);
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &c256);

  NSString *const SHA256FormatString =
    @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

  NSString *sha256 = [[NSString alloc] initWithFormat:SHA256FormatString,
      digest[0], digest[1], digest[2], digest[3],
      digest[4], digest[5], digest[6], digest[7],
      digest[8], digest[9], digest[10], digest[11],
      digest[12], digest[13], digest[14], digest[15],
      digest[16], digest[17], digest[18], digest[19],
      digest[20], digest[21], digest[22], digest[23],
      digest[24], digest[25], digest[26], digest[27],
      digest[28], digest[29], digest[30], digest[31]];

  return sha256;
}

@end
