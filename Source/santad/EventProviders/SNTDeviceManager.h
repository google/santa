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
#import <DiskArbitration/DiskArbitration.h>
#import <Foundation/Foundation.h>

#include <EndpointSecurity/EndpointSecurity.h>

/*
 * Manages DiskArbitration and EndpointSecurity to monitor/block/remount USB
 * storage devices.
 */
@interface SNTDeviceManager : NSObject

@property(nonatomic, readwrite) BOOL subscribed;
@property(nonatomic, readwrite) BOOL blockUSBMount;
@property(nonatomic, readwrite) NSArray<NSString *> *remountArgs;

- (instancetype)init;
- (void)listen;
- (BOOL)subscribed;

@end
