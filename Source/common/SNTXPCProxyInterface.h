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
- (void)removeListenerOfType:(SNTXPCType)type;
- (void)lookupListenerOfType:(SNTXPCType)type
                       reply:(void (^)(NSXPCListenerEndpoint *listener))reply;

@end

///
///  Protocol implemented by xpc services started by santaxpcproxy
///
@protocol SNTXPCProxyChildServiceProtocol

- (void)anonymousListener:(void (^)(NSXPCListenerEndpoint *listener))reply;

@end

@interface SNTXPCProxyInterface : NSObject

+ (MOLXPCConnection *)configuredConnection;

///
///  Returns an initialized NSXPCInterface for the SNTXPCProxyProtocol protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)proxyInterface;

///
///  Returns an initialized NSXPCInterface for the SNTXPCProxyChildServiceProtocol protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)proxyChildServiceInterface;

@end

NS_ASSUME_NONNULL_END
