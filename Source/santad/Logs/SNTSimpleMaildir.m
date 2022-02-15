/// Copyright 2021 Google Inc. All rights reserved.
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

#import "Source/santad/Logs/SNTSimpleMaildir.h"

#include <malloc/malloc.h>
#include <stdio.h>

#import "Source/common/SNTLogging.h"

/** Helper for creating errors. */
static NSError *MakeError(NSString *description) {
  return [NSError errorWithDomain:@"com.google.santa"
                             code:1
                         userInfo:@{NSLocalizedDescriptionKey : description}];
}

size_t SNTRoundUpToNextPage(size_t size) {
  const size_t pageSize = 4096;

  if (size % pageSize == 0) {
    return size;
  }
  return pageSize * ((int)(size / pageSize) + 1);
}

NS_ASSUME_NONNULL_BEGIN

@implementation SNTSimpleMaildir {
  // TODO(mlwhite): Add support for metrics

  /** The prefix to use for new log files. */
  NSString *_filenamePrefix;

  /** The base, tmp and new directory for spooling files. */
  NSString *_baseDirectory;
  NSString *_tmpDirectory;
  NSString *_newDirectory;

  /**
   * Timer that flushes every `maxTimeBetweenFlushes` seconds.
   * Used to avoid excessive latency exporting events.
   */
  NSTimer *_flushTimer;

  /** The size threshold after which to start a new log file. */
  size_t _fileSizeThreshold;

  /** Threshold for the estimated spool size. */
  size_t _spoolSizeThreshold;

  /** Temporary storage for SNTSantaMessage in an SNTLogBatch. */
  SNTPBLogBatch *_outputProto;

  /** Current serialized size of all events in the _outputProto batch */
  size_t _outputProtoSerializedSize;

  /** Current size of the file system spooling directory. */
  size_t _estimatedSpoolSize;

  /** Counter for the files we've already opened. Used to generate file names. */
  int _createdFileCount;

  /** Dispatch queue to synchronize flush operations */
  dispatch_queue_t _flushQueue;
}

- (instancetype)initWithBaseDirectory:(NSString *)baseDirectory
                       filenamePrefix:(NSString *)filenamePrefix
                    fileSizeThreshold:(size_t)fileSizeThreshold
               directorySizeThreshold:(size_t)directorySizeThreshold
                maxTimeBetweenFlushes:(NSTimeInterval)maxTimeBetweenFlushes {
  self = [super init];
  if (self) {
    _baseDirectory = baseDirectory;
    _tmpDirectory = [baseDirectory stringByAppendingPathComponent:@"tmp"];
    _newDirectory = [baseDirectory stringByAppendingPathComponent:@"new"];
    _filenamePrefix = [filenamePrefix copy];
    _fileSizeThreshold = fileSizeThreshold;
    _spoolSizeThreshold = directorySizeThreshold;
    _estimatedSpoolSize = SIZE_T_MAX;  // Force a recalculation of the spool directory size
    _createdFileCount = 0;
    _outputProto = [[SNTPBLogBatch alloc] init];
    _outputProtoSerializedSize = 0;

    _flushQueue =
      dispatch_queue_create("com.google.santa.daemon.mail",
                            dispatch_queue_attr_make_with_qos_class(
                              DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL, QOS_CLASS_DEFAULT, 0));

    typeof(self) __weak weakSelf = self;
    _flushTimer = [NSTimer scheduledTimerWithTimeInterval:maxTimeBetweenFlushes
                                                  repeats:YES
                                                    block:^(NSTimer *_Nonnull timer) {
                                                      [weakSelf flush];
                                                    }];
  }
  return self;
}

- (void)dealloc {
  [_flushTimer invalidate];
  [self flush];
}

/** Fires the flush timer programmatically. Used for testing purposes. */
- (void)fireFlushTimer {
  [_flushTimer fire];
}

/**
 * Flushes out buffered data.
 *
 * Returns the number of events that we attempted to flush, and populates the error if that flush
 * failed.
 */
- (int)flushLockedWithError:(NSError **)error {
  NSAssert([_outputProto.recordsArray count] < INT_MAX, @"Too many records");
  int outputEventCount = (int)[_outputProto.recordsArray count];
  if (outputEventCount == 0) {
    return 0;
  }

  if (![self createSpoolDirectoriesWithError:error]) {
    return outputEventCount;
  }

  if (_estimatedSpoolSize > _spoolSizeThreshold) {
    _estimatedSpoolSize = [self spoolDirectorySizeWithError:error];
    if (_estimatedSpoolSize > _spoolSizeThreshold) {
      if (error) {
        *error = MakeError(@"file_system_threshold_exceeded");
      }
      return outputEventCount;
    }
  }

  NSString *filename = [NSString stringWithFormat:@"%@.%u", _filenamePrefix, _createdFileCount];
  NSString *exposedFilepath = [_newDirectory stringByAppendingPathComponent:filename];
  NSString *outputFilepath = [_tmpDirectory stringByAppendingPathComponent:filename];
  NSOutputStream *outputFile = [NSOutputStream outputStreamToFileAtPath:outputFilepath append:NO];
  [outputFile open];
  _createdFileCount++;

  if (!outputFile) {
    if (error) {
      *error = MakeError(@"data_loss_on_open");
    }
    return outputEventCount;
  }

  @try {
    [_outputProto writeToOutputStream:outputFile];
  } @catch (NSException *exception) {
    NSLog(@"Error while writing to %@: %@", outputFilepath, exception);
    if (error) {
      *error = MakeError(@"data_loss_on_write");
    }
  }

  [outputFile close];
  if (![[NSFileManager defaultManager] moveItemAtPath:outputFilepath
                                               toPath:exposedFilepath
                                                error:nil]) {
    [[NSFileManager defaultManager] removeItemAtPath:outputFilepath error:nil];
    // TODO: delete files in /tmp when move fails. Spool directory could be removed
    // by Santa on startup.
    if (error) {
      *error = MakeError(@"data_loss_on_move");
    }
  }

  if (error && !*error) {
    _estimatedSpoolSize += _outputProtoSerializedSize;
  }
  // Clear output buffer.
  _outputProto = [[SNTPBLogBatch alloc] init];
  _outputProtoSerializedSize = 0;
  return outputEventCount;
}

- (void)flush {
  dispatch_sync(_flushQueue, ^{
    [self flushLockedWithError:nil];
  });
}

- (BOOL)createDirectory:(NSString *)dir withError:(NSError **)error {
  BOOL isDir;
  if (![[NSFileManager defaultManager] fileExistsAtPath:dir isDirectory:&isDir]) {
    return [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                     withIntermediateDirectories:NO
                                                      attributes:nil
                                                           error:error];
  } else if (!isDir) {
    if (error) {
      *error = MakeError([NSString stringWithFormat:@"%@ is not a directory", dir]);
    }
    return NO;
  }

  return YES;
}

- (BOOL)createSpoolDirectoriesWithError:(NSError **)error {
  return [self createDirectory:_baseDirectory withError:error] &&
         [self createDirectory:_tmpDirectory withError:error] &&
         [self createDirectory:_newDirectory withError:error];
}

- (size_t)spoolDirectorySizeWithError:(NSError **)error {
  size_t totalSize = 0;
  NSFileManager *fm = [NSFileManager defaultManager];
  NSError *enumerationError = nil;
  NSArray<NSString *> *filenames = [fm contentsOfDirectoryAtPath:_newDirectory
                                                           error:&enumerationError];
  if (enumerationError) {
    *error = MakeError(@"spool_dir_enumeration_error");
    return 0;
  }

  for (NSString *filename in filenames) {
    NSError *attributesError = nil;
    NSDictionary<NSFileAttributeKey, id> *attributes =
      [fm attributesOfItemAtPath:[_newDirectory stringByAppendingPathComponent:filename]
                           error:&attributesError];
    if (attributesError) {
      if (error) {
        *error = MakeError(@"spool_dir_attribute_retrieval_error");
      }
      continue;
    }

    totalSize += SNTRoundUpToNextPage([attributes fileSize]);
  }
  return totalSize;
}

- (void)logEvent:(SNTPBSantaMessage *)event {
  dispatch_sync(_flushQueue, ^{
    if (_outputProtoSerializedSize > _fileSizeThreshold) {
      [self flushLockedWithError:nil];
    }

    [_outputProto.recordsArray addObject:event];
    // Note: +2 added to account for serialization of extra record in the _outputProto array
    _outputProtoSerializedSize += [event serializedSize] + 2;
  });
}

/** Intentionally left no-op method for this class. */
- (void)logString:(NSString *)logLine {
}

@end

NS_ASSUME_NONNULL_END