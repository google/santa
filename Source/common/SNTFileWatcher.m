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

@interface SNTFileWatcher ()
@property NSString *filePath;
@property dispatch_source_t monitoringSource;

@property(strong) void (^eventHandler)(void);
@property(strong) void (^internalEventHandler)(void);
@property(strong) void (^internalCancelHandler)(void);
@end

@implementation SNTFileWatcher

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (instancetype)initWithFilePath:(NSString *)filePath handler:(void (^)(void))handler {
  self = [super init];
  if (self) {
    _filePath = filePath;
    _eventHandler = handler;

    if (!_filePath || !_eventHandler) return nil;

    [self beginWatchingFile];
  }
  return self;
}

- (void)dealloc {
  [self stopWatchingFile];
}

- (void)beginWatchingFile {
  __weak __typeof(self) weakSelf = self;
  int mask = (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE |
              DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_RENAME);
  dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);

  self.internalEventHandler = ^{
    unsigned long l = dispatch_source_get_data(weakSelf.monitoringSource);
    if (l & DISPATCH_VNODE_DELETE || l & DISPATCH_VNODE_RENAME) {
      if (weakSelf.monitoringSource) dispatch_source_cancel(weakSelf.monitoringSource);
    } else {
      [weakSelf performSelectorOnMainThread:@selector(trigger) withObject:nil waitUntilDone:NO];
    }
  };

  self.internalCancelHandler = ^{
    int fd;

    if (weakSelf.monitoringSource) {
      fd = (int)dispatch_source_get_handle(weakSelf.monitoringSource);
      close(fd);
    }

    const char *filePathCString = [weakSelf.filePath fileSystemRepresentation];
    while ((fd = open(filePathCString, O_EVTONLY)) < 0) {
      usleep(1000);
    }

    weakSelf.monitoringSource =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd, mask, queue);
    dispatch_source_set_event_handler(weakSelf.monitoringSource, weakSelf.internalEventHandler);
    dispatch_source_set_cancel_handler(weakSelf.monitoringSource, weakSelf.internalCancelHandler);
    dispatch_resume(weakSelf.monitoringSource);

    [weakSelf performSelectorOnMainThread:@selector(trigger) withObject:nil waitUntilDone:NO];
  };

  dispatch_async(queue, self.internalCancelHandler);
}

- (void)stopWatchingFile {
  if (!self.monitoringSource) return;

  int fd = (int)dispatch_source_get_handle(self.monitoringSource);
  dispatch_source_set_event_handler_f(self.monitoringSource, NULL);
  dispatch_source_set_cancel_handler(self.monitoringSource, ^{
    close(fd);
  });

  dispatch_source_cancel(self.monitoringSource);
  self.monitoringSource = nil;
}

- (void)trigger {
  if (self.eventHandler) {
    self.eventHandler();
  }
}

@end
