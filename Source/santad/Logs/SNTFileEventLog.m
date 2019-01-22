/// Copyright 2018 Google Inc. All rights reserved.
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

#import "Source/santad/Logs/SNTFileEventLog.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"

@interface SNTFileEventLog ()
@property NSFileHandle *fh;
@property(readonly, nonatomic) dispatch_queue_t q;
@property dispatch_source_t source;
@property(readonly, nonatomic) dispatch_source_t timer;
@property(readonly, nonatomic) NSString *path;
@property(readonly, nonatomic) NSMutableData *buffer;
@end

@implementation SNTFileEventLog

- (instancetype)init {
  self = [super init];
  if (self) {
    _q = dispatch_queue_create("com.google.santa.file_event_log", DISPATCH_QUEUE_SERIAL);
    _path = [[SNTConfigurator configurator] eventLogPath];
    _fh = [self fileHandleForPath:_path];
    [self watchLogFile];
    // 8k buffer to batch logs for writing.
    _buffer = [NSMutableData dataWithCapacity:8192];
    // To avoid long lulls in the log being updated, flush the buffer every second.
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _q);
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, 0), NSEC_PER_SEC * 1, 0);
    WEAKIFY(self);
    dispatch_source_set_event_handler(_timer, ^{
      STRONGIFY(self);
      [self flushBuffer];
    });
    dispatch_resume(_timer);
  }
  return self;
}

- (NSFileHandle *)fileHandleForPath:(NSString *)path {
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path]) {
    [fm createFileAtPath:path contents:nil attributes:nil];
  }
  NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
  [fh seekToEndOfFile];
  return fh;
}

- (void)watchLogFile {
  if (self.source) {
    dispatch_source_set_event_handler_f(self.source, NULL);
    dispatch_source_cancel(self.source);
  }
  self.source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE,
                                       self.fh.fileDescriptor,
                                       DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME,
                                       self.q);
  WEAKIFY(self);
  dispatch_source_set_event_handler(self.source, ^{
    STRONGIFY(self);
    [self.fh closeFile];
    self.fh = [self fileHandleForPath:self.path];
    [self watchLogFile];
  });
  dispatch_resume(self.source);
}

- (void)writeLog:(NSString *)log {
  dispatch_async(self.q, ^{
    NSString *dateString = [self.dateFormatter stringFromDate:[NSDate date]];
    NSString *outLog = [NSString stringWithFormat:@"[%@] I santad: %@\n", dateString, log];
    [self.buffer appendBytes:outLog.UTF8String
                      length:[outLog lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];
    // Avoid excessive calls to write() by batching logs.
    if (self.buffer.length >= 4096) {
      [self flushBuffer];
    }
  });
}

- (void)flushBuffer {
  write(self.fh.fileDescriptor, self.buffer.bytes, self.buffer.length);
  [self.buffer setLength:0];
}

@end
