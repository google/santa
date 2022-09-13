/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/common/SNTKVOManager.h"

#import "Source/common/SNTLogging.h"

// This is a small class used to hold information needed when an observed value is changed
@interface SNTObserverInfo : NSObject
@property KVOCallback callback;
@property Class expectedType;
@end

@implementation SNTObserverInfo
- (instancetype)initWithExpectedType:(Class)expectedType callback:(KVOCallback)callback {
  self = [super init];
  if (self) {
    _expectedType = expectedType;
    _callback = callback;
  }
  return self;
}
@end

@interface SNTKVOManager ()
@property NSMutableDictionary<NSString *, SNTObserverInfo *> *observerInfo;
@property NSKeyValueObservingOptions bits;
@end

@implementation SNTKVOManager

+ (instancetype)defaultManager {
  static SNTKVOManager *kvoManager;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    kvoManager = [[SNTKVOManager alloc] init];
  });
  return kvoManager;
}

- (instancetype)init {
  self = [super self];
  if (self) {
    _observerInfo = [[NSMutableDictionary alloc] init];
    _bits = (NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld);
  }
  return self;
}

- (BOOL)addObserverForObject:(id)object
                    selector:(SEL)selector
                        type:(Class)expectedType
                    callback:(KVOCallback)callback {
  NSString *selectorName = NSStringFromSelector(selector);
  if (![object respondsToSelector:selector]) {
    LOGE(@"Attempt to add observer for an unknown selector (%@) for object (%@)", selectorName,
         [object class]);
    return NO;
  }

  SNTObserverInfo *info = [[SNTObserverInfo alloc] initWithExpectedType:expectedType
                                                               callback:callback];

  [self.observerInfo setValue:info forKey:selectorName];

  [object addObserver:self forKeyPath:selectorName options:self.bits context:NULL];

  return YES;
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary<NSString *, id> *)change
                       context:(void *)context {
  SNTObserverInfo *info = [self.observerInfo objectForKey:keyPath];

  id oldValue = [change[NSKeyValueChangeOldKey] isKindOfClass:info.expectedType]
                  ? change[NSKeyValueChangeOldKey]
                  : nil;
  id newValue = [change[NSKeyValueChangeNewKey] isKindOfClass:info.expectedType]
                  ? change[NSKeyValueChangeNewKey]
                  : nil;

  info.callback(oldValue, newValue);
}

@end
