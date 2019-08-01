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

#import "SNTXPCProxyInterface.h"

NSString *const kSantaXPCProxyMachService = @"com.google.santa.xpcproxy";

@implementation SNTXPCProxyInterface

+ (MOLXPCConnection *)configuredConnection {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithName:kSantaXPCProxyMachService
                                                          privileged:YES];
  c.remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SNTXPCProxyProtocol)];
  return c;
}

+ (NSXPCInterface *)proxyInterface {
  return [NSXPCInterface interfaceWithProtocol:@protocol(SNTXPCProxyProtocol)];
}

+ (NSXPCInterface *)proxyChildServiceInterface {
  return [NSXPCInterface interfaceWithProtocol:@protocol(SNTXPCProxyChildServiceProtocol)];
}

@end
