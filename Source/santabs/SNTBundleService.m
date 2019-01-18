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

#import "Source/santabs/SNTBundleService.h"

#include <stdatomic.h>

#import <CommonCrypto/CommonDigest.h>
#import <pthread/pthread.h>

#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"

@interface SNTBundleService ()
@property MOLXPCConnection *notifierConnection;
@property MOLXPCConnection *listener;
@property(nonatomic) dispatch_queue_t queue;
@end

@implementation SNTBundleService

- (instancetype)init {
  self = [super init];
  if (self) {
    _queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
  }
  return self;
}

#pragma mark Connection handling

// Create a listener for SantaGUI to connect
- (void)createConnection {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Create listener for return connection from SantaGUI.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.listener = [[MOLXPCConnection alloc] initServerWithListener:listener];
  self.listener.unprivilegedInterface = self.listener.privilegedInterface = [SNTXPCBundleServiceInterface bundleServiceInterface];
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
  [self performSelectorOnMainThread:@selector(createConnection) withObject:nil waitUntilDone:NO];
}

#pragma mark SNTBundleServiceXPC Methods

// Connect to the SantaGUI
- (void)setBundleNotificationListener:(NSXPCListenerEndpoint *)listener {
  dispatch_async(dispatch_get_main_queue(), ^{
    MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithListener:listener];
    c.remoteInterface = [SNTXPCNotifierInterface bundleNotifierInterface];
    [c resume];
    self.notifierConnection = c;
    [self createConnection];
  });
}

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                             reply:(SNTBundleHashBlock)reply {
  NSProgress *progress =
      [NSProgress currentProgress] ? [NSProgress progressWithTotalUnitCount:100] : nil;

  NSDate *startTime = [NSDate date];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  dispatch_async(self.queue, ^{
    // Use the highest bundle we can find.
    SNTFileInfo *b = [[SNTFileInfo alloc] initWithPath:event.fileBundlePath];
    b.useAncestorBundle = YES;
    event.fileBundlePath = b.bundlePath;

    // If path to the bundle is unavailable, stop. SantaGUI will revert to
    // using the offending blockable.
    if (!event.fileBundlePath) {
      reply(nil, nil, 0);
      dispatch_semaphore_signal(sema);
      return;
    }

    // Reuse the bundle infomation when creating the related binary events.
    event.fileBundleID = b.bundleIdentifier;
    event.fileBundleName = b.bundleName;
    event.fileBundleVersion = b.bundleVersion;
    event.fileBundleVersionString = b.bundleShortVersionString;

    // For most apps this should be "Contents/MacOS/AppName"
    if (b.bundle.executablePath.length > b.bundlePath.length) {
      event.fileBundleExecutableRelPath =
          [b.bundle.executablePath substringFromIndex:b.bundlePath.length + 1];
    }

    NSDictionary *relatedEvents = [self findRelatedBinaries:event progress:progress];
    NSString *bundleHash = [self calculateBundleHashFromSHA256Hashes:relatedEvents.allKeys
                                                            progress:progress];

    NSNumber *ms = [NSNumber numberWithDouble:[startTime timeIntervalSinceNow] * -1000.0];

    reply(bundleHash, relatedEvents.allValues, ms);
    dispatch_semaphore_signal(sema);
  });

  // Master timeout of 10 min. Don't block the calling thread. NSProgress updates will be coming
  // in over this thread.
  dispatch_async(self.queue, ^{
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC))) {
      [progress cancel];
    }
  });
}

#pragma mark Internal Methods

/**
  Find binaries within a bundle given the bundle's event. It will run until a timeout occurs,
  or until the NSProgress is cancelled. Search is done within the bundle concurrently.

  @param event The SNTStoredEvent to begin searching.
  @return An NSDictionary object with keys of fileSHA256 and values of SNTStoredEvent objects.
*/
- (NSDictionary *)findRelatedBinaries:(SNTStoredEvent *)event progress:(NSProgress *)progress {
  // Find all files and folders within the fileBundlePath
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray *subpaths = [fm subpathsOfDirectoryAtPath:event.fileBundlePath error:NULL];

  // This array is used to store pointers to executable SNTFileInfo objects. There will be one block
  // dispatched per file in dirEnum. These blocks will write pointers to this array concurrently.
  // No locks are used since every file has a slot.
  //
  // Xcode.app has roughly 500k files, 8bytes per pointer is ~4MB for this array. This size to space
  // ratio seems appropriate as Xcode.app is in the upper bounds of bundle size.
  __block void **fis = calloc(subpaths.count, sizeof(void *));

  // Counts used as additional progress information in SantaGUI
  __block atomic_llong binaryCount = 0;
  __block volatile int64_t sentBinaryCount = 0;

  // Account for 80% of the work
  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:80];
    p = [NSProgress progressWithTotalUnitCount:subpaths.count * 100];
  }

  // Dispatch a block for every file in dirEnum.
  dispatch_apply(subpaths.count, self.queue, ^(size_t i) {
    @autoreleasepool {
      if (progress.isCancelled) return;

      dispatch_sync(dispatch_get_main_queue(), ^{
        p.completedUnitCount++;
        if (progress && ((i % 500) == 0 || binaryCount > sentBinaryCount)) {
          sentBinaryCount = binaryCount;
          [[self.notifierConnection remoteObjectProxy] updateCountsForEvent:event
                                                                binaryCount:binaryCount
                                                                  fileCount:i
                                                                hashedCount:0];
        }
      });

      NSString *subpath = subpaths[i];

      NSString *file =
          [event.fileBundlePath stringByAppendingPathComponent:subpath].stringByStandardizingPath;
      SNTFileInfo *fi = [[SNTFileInfo alloc] initWithResolvedPath:file error:NULL];
      if (!fi.isExecutable) return;

      fis[i] = (__bridge_retained void *)fi;
      atomic_fetch_add(&binaryCount, 1);
    }
  });

  [progress resignCurrent];

  NSMutableArray *fileInfos = [NSMutableArray arrayWithCapacity:binaryCount];
  for (NSUInteger i = 0; i < subpaths.count; i++) {
    if (fis[i]) [fileInfos addObject:(__bridge_transfer SNTFileInfo *)fis[i]];
  }

  free(fis);

  return [self generateEventsFromBinaries:fileInfos blockingEvent:event progress:progress];
}

- (NSDictionary *)generateEventsFromBinaries:(NSArray *)fis
                               blockingEvent:(SNTStoredEvent *)event
                                    progress:(NSProgress *)progress {
  if (progress.isCancelled) return nil;

  NSMutableDictionary *relatedEvents = [NSMutableDictionary dictionaryWithCapacity:fis.count];

  // Account for 15% of the work
  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:15];
    p = [NSProgress progressWithTotalUnitCount:fis.count * 100];
  }

  dispatch_apply(fis.count, self.queue, ^(size_t i) {
    @autoreleasepool {
      if (progress.isCancelled) return;

      SNTFileInfo *fi = fis[i];

      SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
      se.filePath = fi.path;
      se.fileSHA256 = fi.SHA256;
      se.occurrenceDate = [NSDate distantFuture];
      se.decision = SNTEventStateBundleBinary;

      se.fileBundlePath = event.fileBundlePath;
      se.fileBundleExecutableRelPath = event.fileBundleExecutableRelPath;
      se.fileBundleID = event.fileBundleID;
      se.fileBundleName = event.fileBundleName;
      se.fileBundleVersion = event.fileBundleVersion;
      se.fileBundleVersionString = event.fileBundleVersionString;

      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      se.signingChain = cs.certificates;

      dispatch_sync(dispatch_get_main_queue(), ^{
        relatedEvents[se.fileSHA256] = se;
        p.completedUnitCount++;
        if (progress) {
          [[self.notifierConnection remoteObjectProxy] updateCountsForEvent:event
                                                                binaryCount:fis.count
                                                                  fileCount:0
                                                                hashedCount:i];
        }
      });
    }
  });

  [progress resignCurrent];

  return relatedEvents;
}

- (NSString *)calculateBundleHashFromSHA256Hashes:(NSArray *)hashes
                                         progress:(NSProgress *)progress {
  if (!hashes.count) return nil;

  // Account for 5% of the work
  NSProgress *p;
  if (progress) {
    [progress becomeCurrentWithPendingUnitCount:5];
    p = [NSProgress progressWithTotalUnitCount:5 * 100];
  }

  NSMutableArray *sortedHashes = [hashes mutableCopy];
  [sortedHashes sortUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
  NSString *sha256Hashes = [sortedHashes componentsJoinedByString:@""];

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

  p.completedUnitCount++;
  [progress resignCurrent];
  return sha256;
}

@end
