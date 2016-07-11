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

#import "SNTFileWatcher.h"

#import "SNTStrengthify.h"

@interface SNTFileWatcher ()
@property NSString *filePath;
@property(strong) void (^handler)(unsigned long);

@property dispatch_source_t source;
@end

@implementation SNTFileWatcher

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (instancetype)initWithFilePath:(nonnull NSString *)filePath
                         handler:(nonnull void (^)(unsigned long))handler {
  self = [super init];
  if (self) {
    _filePath = filePath;
    _handler = handler;
    [self startWatchingFile];
  }
  return self;
}

- (void)dealloc {
  [self stopWatchingFile];
}

- (void)startWatchingFile {
  dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
  int mask = (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME |
              DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_ATTRIB);

  dispatch_async(queue, ^{
    int fd = -1;
    while ((fd = open([self.filePath fileSystemRepresentation], O_EVTONLY | O_CLOEXEC)) < 0) {
      usleep(200000);  // wait 200ms
    }
    self.source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd, mask, queue);

    WEAKIFY(self);

    dispatch_source_set_event_handler(self.source, ^{
      STRONGIFY(self);
      unsigned long data = dispatch_source_get_data(self.source);
      self.handler(data);
      if (data & DISPATCH_VNODE_DELETE || data & DISPATCH_VNODE_RENAME) {
        [self stopWatchingFile];
        [self startWatchingFile];
      }
      sleep(2);
    });

    dispatch_source_set_registration_handler(self.source, ^{
      STRONGIFY(self);
      self.handler(0);
    });

    dispatch_source_set_cancel_handler(self.source, ^{
      STRONGIFY(self);
      int fd = (int)dispatch_source_get_handle(self.source);
      if (fd > 0) close(fd);
    });
    
    dispatch_resume(self.source);
  });
}

- (void)stopWatchingFile {
  if (!self.source) return;

  int fd = (int)dispatch_source_get_handle(self.source);
  dispatch_source_set_event_handler_f(self.source, NULL);
  dispatch_source_set_cancel_handler(self.source, ^{
    close(fd);
  });

  dispatch_source_cancel(self.source);
  self.source = nil;
}

@end
