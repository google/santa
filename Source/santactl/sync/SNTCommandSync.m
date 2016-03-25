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

#import "SNTAuthenticatingURLSession.h"
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
@property NSURLSession *session;
@property SNTXPCConnection *daemonConn;
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
  return nil;
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  SNTConfigurator *config = [SNTConfigurator configurator];

  // Ensure we have no privileges
  if (!DropRootPrivileges()) {
    LOGE(@"Failed to drop root privileges. Exiting.");
    exit(1);
  }

  // Dropping root privileges to the 'nobody' user causes the default NSURLCache to throw
  // sandbox errors, which are benign but annoying. This line disables the cache entirely.
  [NSURLCache setSharedURLCache:[[NSURLCache alloc] initWithMemoryCapacity:0
                                                              diskCapacity:0
                                                                  diskPath:nil]];

  SNTCommandSync *s = [[self alloc] init];

  SNTAuthenticatingURLSession *authURLSession = [[SNTAuthenticatingURLSession alloc] init];

  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;

  // Configure server auth
  if ([config syncServerAuthRootsFile]) {
    NSError *error = nil;

    NSData *rootsData = [NSData dataWithContentsOfFile:[config syncServerAuthRootsFile]
                                               options:0
                                                 error:&error];
    authURLSession.serverRootsPemData = rootsData;

    if (!rootsData) {
      LOGE(@"Couldn't open server root certificate file %@ with error: %@.",
           [config syncServerAuthRootsFile],
           [error localizedDescription]);
      exit(1);
    }
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

  s.session = [authURLSession session];
  s.daemonConn = daemonConn;

  // Gather some data needed during some sync stages
  s.syncState = [[SNTCommandSyncState alloc] init];

  s.syncState.syncBaseURL = config.syncBaseURL;
  if (!s.syncState.syncBaseURL) {
    LOGE(@"Missing SyncBaseURL. Can't sync without it.");
    exit(1);
  } else if (![s.syncState.syncBaseURL.scheme isEqual:@"https"]) {
    LOGW(@"SyncBaseURL is not over HTTPS!");
  }
  authURLSession.serverHostname = s.syncState.syncBaseURL.host;

  s.syncState.machineID = config.machineID;
  if ([s.syncState.machineID length] == 0) {
    LOGE(@"Missing Machine ID. Can't sync without it.");
    exit(1);
  }

  s.syncState.machineOwner = config.machineOwner;
  if ([s.syncState.machineOwner length] == 0) {
    s.syncState.machineOwner = @"";
    LOGW(@"Missing Machine Owner.");  
  }

  if ([arguments containsObject:@"singleevent"]) {
    NSUInteger idx = [arguments indexOfObject:@"singleevent"];
    idx++;
    NSString *obj = arguments[idx];
    if (obj.length != 64) {
      LOGI(@"singleevent passed without SHA-256 as next argument");
      exit(1);
    }
    [s eventUploadSingleEvent:obj];
  } else {
    [s preflight];
  }
}

- (void)preflight {
  [SNTCommandSyncPreflight performSyncInSession:self.session
                                      syncState:self.syncState
                                     daemonConn:self.daemonConn
                              completionHandler:^(BOOL success) {
      if (success) {
        if (self.syncState.uploadLogURL) {
          [self logUpload];
        } else {
          [self eventUpload];
        }
      } else {
        LOGE(@"Preflight failed, aborting run");
        exit(1);
      }
  }];
}

- (void)logUpload {
  [SNTCommandSyncLogUpload performSyncInSession:self.session
                                      syncState:self.syncState
                                     daemonConn:self.daemonConn
                              completionHandler:^(BOOL success) {
      if (success) {
      } else {
        LOGE(@"Log upload failed, continuing anyway");
      }
      [self eventUpload];

  }];
}

- (void)eventUpload {
  [SNTCommandSyncEventUpload performSyncInSession:self.session
                                        syncState:self.syncState
                                       daemonConn:self.daemonConn
                                completionHandler:^(BOOL success) {
      if (success) {
        [self ruleDownload];
      } else {
        LOGE(@"Event upload failed, aborting run");
        exit(1);
      }
  }];
}

- (void)eventUploadSingleEvent:(NSString *)sha256 {
  [SNTCommandSyncEventUpload uploadSingleEventWithSHA256:sha256
                                                 session:self.session
                                               syncState:self.syncState
                                              daemonConn:self.daemonConn
                                       completionHandler:^(BOOL success) {
      if (success) {
        exit(0);
      } else {
        LOGW(@"Event upload failed");
        exit(1);
      }
  }];
}

- (void)ruleDownload {
  [SNTCommandSyncRuleDownload performSyncInSession:self.session
                                         syncState:self.syncState
                                        daemonConn:self.daemonConn
                                 completionHandler:^(BOOL success) {
      if (success) {
        [self postflight];
      } else {
        LOGE(@"Rule download failed, aborting run");
        exit(1);
      }
  }];
}

- (void)postflight {
  [SNTCommandSyncPostflight performSyncInSession:self.session
                                       syncState:self.syncState
                                      daemonConn:self.daemonConn
                               completionHandler:^(BOOL success) {
      if (success) {
        LOGI(@"Sync completed successfully");
        exit(0);
      } else {
        LOGE(@"Postflight failed");
        exit(1);
      }
  }];
}

@end
