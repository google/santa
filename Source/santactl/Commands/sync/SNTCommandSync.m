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

#import "SNTCommandController.h"

#import <MOLAuthenticatingURLSession.h>

#import "SNTCommandSyncEventUpload.h"
#import "SNTCommandSyncLogUpload.h"
#import "SNTCommandSyncPostflight.h"
#import "SNTCommandSyncPreflight.h"
#import "SNTCommandSyncRuleDownload.h"
#import "SNTCommandSyncState.h"
#import "SNTConfigurator.h"
#import "SNTDropRootPrivs.h"
#import "SNTLogging.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandSync : NSObject<SNTCommand>
@property SNTCommandSyncState *syncState;
@end

@implementation SNTCommandSync

REGISTER_COMMAND_NAME(@"sync")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Synchronizes Santa with a configured server.";
}

+ (NSString *)longHelpText {
  return (@"If Santa is configured to synchronize with a a server, "
          @"this is the command used for syncing.\n\n"
          @"Options:\n"
          @"  --clean: Perform a clean sync, erasing all existing rules and requesting a"
          @"           clean sync from the server.");
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  // Ensure we have no privileges
  if (!DropRootPrivileges()) {
    LOGE(@"Failed to drop root privileges. Exiting.");
    exit(1);
  }

  SNTConfigurator *config = [SNTConfigurator configurator];

  SNTCommandSync *s = [[self alloc] init];

  // Gather some data needed during some sync stages
  s.syncState = [[SNTCommandSyncState alloc] init];

  s.syncState.syncBaseURL = config.syncBaseURL;
  if (s.syncState.syncBaseURL.absoluteString.length == 0) {
    LOGE(@"Missing SyncBaseURL. Can't sync without it.");
    exit(1);
  } else if (![s.syncState.syncBaseURL.scheme isEqual:@"https"]) {
    LOGW(@"SyncBaseURL is not over HTTPS!");
  }

  s.syncState.machineID = config.machineID;
  if (s.syncState.machineID.length == 0) {
    LOGE(@"Missing Machine ID. Can't sync without it.");
    exit(1);
  }

  s.syncState.machineOwner = config.machineOwner;
  if (s.syncState.machineOwner.length == 0) {
    s.syncState.machineOwner = @"";
    LOGW(@"Missing Machine Owner.");
  }

  [[daemonConn remoteObjectProxy] xsrfToken:^(NSString *token) {
    s.syncState.xsrfToken = token;
  }];

  // Dropping root privileges to the 'nobody' user causes the default NSURLCache to throw
  // sandbox errors, which are benign but annoying. This line disables the cache entirely.
  [NSURLCache setSharedURLCache:[[NSURLCache alloc] initWithMemoryCapacity:0
                                                              diskCapacity:0
                                                                  diskPath:nil]];


  MOLAuthenticatingURLSession *authURLSession = [[MOLAuthenticatingURLSession alloc] init];
  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;
  authURLSession.serverHostname = s.syncState.syncBaseURL.host;
  authURLSession.loggingBlock = ^(NSString *line) {
    LOGD(@"%@", line);
  };

  // Configure server auth
  if ([config syncServerAuthRootsFile]) {
    authURLSession.serverRootsPemFile = [config syncServerAuthRootsFile];
  } else if ([config syncServerAuthRootsData]) {
    authURLSession.serverRootsPemData = [config syncServerAuthRootsData];
  }

  // Configure client auth
  if ([config syncClientAuthCertificateFile]) {
    authURLSession.clientCertFile = [config syncClientAuthCertificateFile];
    authURLSession.clientCertPassword = [config syncClientAuthCertificatePassword];
  } else if ([config syncClientAuthCertificateCn]) {
    authURLSession.clientCertCommonName = [config syncClientAuthCertificateCn];
  } else if ([config syncClientAuthCertificateIssuer]) {
    authURLSession.clientCertIssuerCn = [config syncClientAuthCertificateIssuer];
  }

  s.syncState.session = [authURLSession session];
  s.syncState.daemonConn = daemonConn;

  if ([arguments containsObject:@"singleevent"]) {
    NSUInteger idx = [arguments indexOfObject:@"singleevent"] + 1;
    if (idx >= arguments.count) {
      LOGI(@"singleevent takes an argument");
      exit(1);
    }

    NSString *obj = arguments[idx];
    if (obj.length != 64) {
      LOGI(@"singleevent passed without SHA-256 as next argument");
      exit(1);
    }
    return [s eventUploadSingleEvent:obj];
  } else {
    return [s preflight];
  }
}

- (void)preflight {
  SNTCommandSyncPreflight *p = [[SNTCommandSyncPreflight alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Preflight complete");
    if (self.syncState.uploadLogURL) {
      return [self logUpload];
    } else {
      return [self eventUpload];
    }
  } else {
    LOGE(@"Preflight failed, aborting run");
    exit(1);
  }
}

- (void)logUpload {
  SNTCommandSyncLogUpload *p = [[SNTCommandSyncLogUpload alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Log upload complete");
  } else {
    LOGE(@"Log upload failed, continuing anyway");
  }
  return [self eventUpload];
}

- (void)eventUpload {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Event upload complete");
    return [self ruleDownload];
  } else {
    LOGE(@"Event upload failed, aborting run");
    exit(1);
  }
}

- (void)eventUploadSingleEvent:(NSString *)sha256 {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  if ([p syncSingleEventWithSHA256:sha256]) {
    LOGD(@"Event upload complete");
    exit(0);
  } else {
    LOGE(@"Event upload failed");
    exit(1);
  }
}

- (void)ruleDownload {
  SNTCommandSyncRuleDownload *p = [[SNTCommandSyncRuleDownload alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Rule download complete");
    if (self.syncState.bundleBinaryRequests.count) {
      return [self eventUploadBundleBinaries];
    }
    return [self postflight];
  } else {
    LOGE(@"Rule download failed, aborting run");
    exit(1);
  }
}

- (void)eventUploadBundleBinaries {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  if ([p syncBundleEvents]) {
    LOGD(@"Event upload for bundle binaries complete");
  } else {
    LOGW(@"Event upload for bundle binary search failed");
  }
  return [self postflight];
}

- (void)postflight {
  SNTCommandSyncPostflight *p = [[SNTCommandSyncPostflight alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Postflight complete");
    LOGI(@"Sync completed successfully");
    exit(0);
  } else {
    LOGE(@"Postflight failed");
    exit(1);
  }
}

@end
