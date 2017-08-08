/// Copyright 2017 Google Inc. All rights reserved.
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

#import "SNTCommand.h"
#import "SNTCommandController.h"

#import "SNTFileInfo.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandBundleInfo : SNTCommand<SNTCommandProtocol>
@end

@implementation SNTCommandBundleInfo

#ifdef DEBUG
REGISTER_COMMAND_NAME(@"bundleinfo")
#endif

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Searches a bundle for binaries";
}

+ (NSString *)longHelpText {
  return @"Searches a bundle for binaries";
}

- (void)runWithArguments:(NSArray *)arguments {
  NSError *error;
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:arguments.firstObject error:&error];
  if (!fi) {
    printf("%s\n", error.description.UTF8String);
    exit(1);
  } else if (!fi.bundle) {
    printf("Not a bundle\n");
    exit(2);
  }

  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
  se.fileBundlePath = fi.bundlePath;

  [[self.daemonConn remoteObjectProxy]
      hashBundleBinariesForEvent:se
                           reply:^(NSString *hash, NSArray<SNTStoredEvent *> *events,
                                   NSNumber *time) {
    printf("Hashing time: %llu ms\n", time.unsignedLongLongValue);
    printf("%lu events found\n", events.count);
    printf("BundleHash: %s\n", hash.UTF8String);

    for (SNTStoredEvent *event in events) {
      printf("BundleID: %s \n\tSHA-256: %s \n\tPath: %s\n",
             event.fileBundleID.UTF8String, event.fileSHA256.UTF8String, event.filePath.UTF8String);
    }
    exit(0);
  }];
}

@end
