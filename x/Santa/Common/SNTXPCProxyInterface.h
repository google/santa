/// Copyright 2019 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#import <MOLXPCConnection/MOLXPCConnection.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const kSantaXPCProxyMachService;

typedef NS_ENUM(NSInteger, SNTXPCType) {
  SNTXPCTypeUnknown,

  SNTXPCTypeDaemon = 1,
  SNTXPCTypeGUI = 2,
  SNTXPCTypeBundleService = 3,
  SNTXPCTypeQurantineService = 4,
  SNTXPCTypeSyncService = 5,
};

///
///  Protocol implemented by santaxpcproxy
///
@protocol SNTXPCProxyProtocol

- (void)registerListener:(NSXPCListenerEndpoint *)listener ofType:(SNTXPCType)type;
- (NSXPCListenerEndpoint *)lookupListenerOfType:(SNTXPCType)type;

@end

@interface SNTXPCProxyInterface : NSObject

+ (MOLXPCConnection *)configuredConnection;

@end

NS_ASSUME_NONNULL_END
