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

#import "SNTXPCControlInterface.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTRule.h"
#import "SNTStoredEvent.h"

@implementation SNTXPCControlInterface

+ (NSString *)serviceId {
  return @"SantaXPCControl";
}

+ (NSXPCInterface *)controlInterface {
  NSXPCInterface *r = [NSXPCInterface interfaceWithProtocol:@protocol(SNTDaemonControlXPC)];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil]
        forSelector:@selector(databaseEventsPending:)
      argumentIndex:0
            ofReply:YES];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTRule class], nil]
        forSelector:@selector(databaseRuleAddRules:cleanSlate:reply:)
      argumentIndex:0
            ofReply:NO];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil]
        forSelector:@selector(hashBundleBinariesForEvent:reply:)
      argumentIndex:1
            ofReply:YES];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil]
        forSelector:@selector(syncBundleEvent:relatedEvents:)
      argumentIndex:1
            ofReply:NO];

  return r;
}

+ (MOLXPCConnection *)configuredConnection {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithName:[self serviceId]
                                                          privileged:YES];
  c.remoteInterface = [self controlInterface];
  return c;
}

@end
