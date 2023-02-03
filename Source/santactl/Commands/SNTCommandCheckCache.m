/// Copyright 2016-2022 Google Inc. All rights reserved.
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

#include <sys/stat.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

#ifdef DEBUG

@interface SNTCommandCheckCache : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandCheckCache

REGISTER_COMMAND_NAME(@"checkcache")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Prints the status of a file in the cache.";
}

+ (NSString *)longHelpText {
  return (@"Checks the cache for desired file.\n"
          @"Returns 0 if successful, 1 otherwise");
}

- (void)runWithArguments:(NSArray *)arguments {
  SantaVnode vnodeID = [self vnodeIDForFile:arguments.firstObject];
  [[self.daemonConn synchronousRemoteObjectProxy]
    checkCacheForVnodeID:vnodeID
               withReply:^(SNTAction action) {
                 if (action == SNTActionRespondAllow) {
                   LOGI(@"File exists in [allowlist] cache");
                   exit(0);
                 } else if (action == SNTActionRespondDeny) {
                   LOGI(@"File exists in [blocklist] cache");
                   exit(0);
                 } else if (action == SNTActionRespondAllowCompiler) {
                   LOGI(@"File exists in [allowlist compiler] cache");
                   exit(0);
                 } else if (action == SNTActionUnset) {
                   LOGE(@"File does not exist in cache");
                   exit(1);
                 }
               }];
}

- (SantaVnode)vnodeIDForFile:(NSString *)path {
  struct stat fstat = {};
  stat(path.fileSystemRepresentation, &fstat);
  SantaVnode ret = {.fsid = fstat.st_dev, .fileid = fstat.st_ino};
  return ret;
}

@end

#endif
