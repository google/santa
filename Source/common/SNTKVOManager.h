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

#import <Foundation/Foundation.h>

// The callback type when KVO notifications are received for observed key paths.
// The first parameter is the previous value, the second paramter is the new value.
typedef void (^KVOCallback)(id oldValue, id newValue);

@interface SNTKVOManager : NSObject

// Add an observer for the selector on the given object. When a KVO notification
// is received, the callback is called. If the notification contains objects that
// are not of the expectedType, nil is passed as the argument to the callback.
// The observer is removed when the returned instance is deallocated.
- (instancetype)initWithObject:(id)object
                      selector:(SEL)selector
                          type:(Class)expectedType
                      callback:(KVOCallback)callback;

- (instancetype)init NS_UNAVAILABLE;

@end
