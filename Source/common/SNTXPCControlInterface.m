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

#import "Source/common/SNTXPCControlInterface.h"

#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"

NSString *const kBundleID = @"com.google.santa.daemon";

@implementation SNTXPCControlInterface

+ (NSString *)serviceID {
  if (@available(macOS 10.15, *)) {
    MOLCodesignChecker *cs = [[MOLCodesignChecker alloc] initWithSelf];
    // "teamid.com.google.santa.daemon.xpc"
    NSString *t = cs.signingInformation[@"teamid"];
    return [NSString stringWithFormat:@"%@.%@.xpc", t, kBundleID];
  }
  return kBundleID;
}

+ (NSString *)systemExtensionID {
  return kBundleID;
}

+ (void)initializeControlInterface:(NSXPCInterface *)r {
  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class], nil]
        forSelector:@selector(databaseEventsPending:)
      argumentIndex:0
            ofReply:YES];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTRule class], nil]
        forSelector:@selector(databaseRuleAddRules:cleanSlate:reply:)
      argumentIndex:0
            ofReply:NO];
}

+ (NSXPCInterface *)controlInterface {
  NSXPCInterface *r = [NSXPCInterface interfaceWithProtocol:@protocol(SNTDaemonControlXPC)];
  [self initializeControlInterface:r];

  return r;
}

+ (MOLXPCConnection *)configuredConnection {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithName:[self serviceID]
                                                          privileged:YES];
  c.remoteInterface = [self controlInterface];
  return c;
}

@end
