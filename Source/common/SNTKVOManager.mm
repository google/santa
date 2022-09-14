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

@interface SNTKVOManager ()
@property KVOCallback callback;
@property Class expectedType;
@property NSString *keyPath;
@property id object;
@end

@implementation SNTKVOManager

- (instancetype)initWithObject:(id)object
                      selector:(SEL)selector
                          type:(Class)expectedType
                      callback:(KVOCallback)callback {
  self = [super self];
  if (self) {
    NSString *selectorName = NSStringFromSelector(selector);
    if (![object respondsToSelector:selector]) {
      LOGE(@"Attempt to add observer for an unknown selector (%@) for object (%@)", selectorName,
           [object class]);
      self = nil;
      return self;
    }

    _object = object;
    _keyPath = selectorName;
    _expectedType = expectedType;
    _callback = callback;

    [object addObserver:self
             forKeyPath:selectorName
                options:(NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld)
                context:NULL];
  }
  return self;
}

- (void)dealloc {
  [self.object removeObserver:self forKeyPath:self.keyPath context:NULL];
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary<NSString *, id> *)change
                       context:(void *)context {
  id oldValue = [change[NSKeyValueChangeOldKey] isKindOfClass:self.expectedType]
                  ? change[NSKeyValueChangeOldKey]
                  : nil;
  id newValue = [change[NSKeyValueChangeNewKey] isKindOfClass:self.expectedType]
                  ? change[NSKeyValueChangeNewKey]
                  : nil;

  self.callback(oldValue, newValue);
}

@end
