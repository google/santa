/// Copyright 2014 Google Inc. All rights reserved.
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
#import "SNTCommandSyncStatus.h"
#import "SNTConfigurator.h"
#import "SNTDropRootPrivs.h"
#import "SNTLogging.h"
#import "SNTSystemInfo.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandSync : NSObject<SNTCommand>
@property NSURLSession *session;
@property SNTXPCConnection *daemonConn;
@property SNTCommandSyncStatus *progress;
@end

@implementation SNTCommandSync

REGISTER_COMMAND_NAME(@"sync");

+ (BOOL)requiresRoot {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Synchronizes Santa with the server";
}

+ (NSString *)longHelpText {
  return @"";
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

  // Configure server auth
  if ([config syncServerAuthRootsFile]) {
    NSError* error = nil;

    NSData *rootsData = [NSData dataWithContentsOfFile:[config syncServerAuthRootsFile] options:0 error:&error];
    authURLSession.serverRootsPemData = rootsData;
      
    if (rootsData == nil) {
        LOGE(@"Couldn't open server root certificate file %@ with error: %@.", [config syncServerAuthRootsFile], [error localizedDescription]);
        exit(1);
    }
  } else if ([config syncServerAuthRootsData]) {
    authURLSession.serverRootsPemData = [config syncServerAuthRootsData];
  }

  // Configure client auth
  if ([config syncClientAuthCertificateCn]) {
    authURLSession.clientCertCommonName = [config syncClientAuthCertificateCn];
  } else if ([config syncClientAuthCertificateIssuer]) {
    authURLSession.clientCertIssuerCn = [config syncClientAuthCertificateIssuer];
  }

  s.session = [authURLSession session];
  s.daemonConn = daemonConn;

  // Gather some data needed during some sync stages
  s.progress = [[SNTCommandSyncStatus alloc] init];

  s.progress.syncBaseURL = config.syncBaseURL;
  if (!s.progress.syncBaseURL) {
    LOGE(@"Missing SyncBaseURL. Can't sync without it.");
    exit(1);
  }
  authURLSession.serverHostname = s.progress.syncBaseURL.host;

  s.progress.machineID = config.machineIDOverride;
  if (!s.progress.machineID || [s.progress.machineID isEqual:@""]) {
    s.progress.machineID = [SNTSystemInfo hardwareUUID];
  }
  if (!s.progress.machineID || [s.progress.machineID isEqual:@""]) {
    LOGE(@"Missing Machine ID. Can't sync without it.");
    exit(1);
  }
  s.progress.machineOwner = config.machineOwner;

  if (arguments.count == 2 && [[arguments firstObject] isEqual:@"singleevent"]) {
    [s eventUploadSingleEvent:arguments[1]];
  } else {
    [s preflight];
  }
}

- (void)preflight {
  [SNTCommandSyncPreflight performSyncInSession:self.session
                                       progress:self.progress
                                     daemonConn:self.daemonConn
                              completionHandler:^(BOOL success) {
                                  if (success) {
                                    LOGI(@"Preflight complete");
                                    if (self.progress.uploadLogURL) {
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
                                       progress:self.progress
                                     daemonConn:self.daemonConn
                              completionHandler:^(BOOL success) {
                                  if (success) {
                                    LOGI(@"Log upload complete");
                                    [self eventUpload];
                                  } else {
                                    LOGE(@"Log upload failed, aborting run");
                                    exit(1);
                                  }
                              }];
}

- (void)eventUpload {
  [SNTCommandSyncEventUpload performSyncInSession:self.session
                                         progress:self.progress
                                       daemonConn:self.daemonConn
                                completionHandler:^(BOOL success) {
                                    if (success) {
                                      LOGI(@"Event upload complete");
                                      [self ruleDownload];
                                    } else {
                                      LOGE(@"Event upload failed, aborting run");
                                      exit(1);
                                    }
                                }];
}

- (void)eventUploadSingleEvent:(NSString *)sha1 {
  [SNTCommandSyncEventUpload uploadSingleEventWithSHA1:sha1
                                               session:self.session
                                              progress:self.progress
                                            daemonConn:self.daemonConn
                                     completionHandler:^(BOOL success) {
                                       if (success) {
                                         LOGI(@"Event upload complete");
                                         exit(0);
                                       } else {
                                         LOGW(@"Event upload failed");
                                         exit(1);
                                       }
                                     }];
}

- (void)ruleDownload {
  [SNTCommandSyncRuleDownload performSyncInSession:self.session
                                          progress:self.progress
                                        daemonConn:self.daemonConn
                                 completionHandler:^(BOOL success) {
                                     if (success) {
                                       LOGI(@"Rule download complete");
                                       [self postflight];
                                     } else {
                                       LOGE(@"Rule download failed, aborting run");
                                       exit(1);
                                     }
                                 }];
}

- (void)postflight {
  [SNTCommandSyncPostflight performSyncInSession:self.session
                                        progress:self.progress
                                      daemonConn:self.daemonConn
                               completionHandler:^(BOOL success) {
                                   if (success) {
                                     LOGI(@"Postflight complete");
                                     LOGI(@"Sync completed successfully");
                                     exit(0);
                                   } else {
                                     LOGE(@"Postflight failed");
                                     exit(1);
                                   }
                               }];
}

@end
