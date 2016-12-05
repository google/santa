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

#import "SNTCommandSyncManager.h"
#import "SNTConfigurator.h"
#import "SNTDropRootPrivs.h"
#import "SNTLogging.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandSync : NSObject<SNTCommand>
@property SNTXPCConnection *listener;
@property SNTCommandSyncManager *syncManager;
@end

@implementation SNTCommandSync

REGISTER_COMMAND_NAME(@"sync")

#pragma mark SNTCommand protocol methods

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
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

  SNTCommandSync *s = [[self alloc] init];
  [daemonConn resume];
  BOOL daemon = [arguments containsObject:@"--daemon"];
  s.syncManager = [[SNTCommandSyncManager alloc] initWithDaemonConnection:daemonConn
                                                                 isDaemon:daemon];

  // Dropping root privileges to the 'nobody' user causes the default NSURLCache to throw
  // sandbox errors, which are benign but annoying. This line disables the cache entirely.
  [NSURLCache setSharedURLCache:[[NSURLCache alloc] initWithMemoryCapacity:0
                                                              diskCapacity:0
                                                                  diskPath:nil]];

  if (!s.syncManager.daemon) return [s.syncManager fullSync];
  [s syncdWithDaemonConnection:daemonConn];
}

#pragma mark daemon methods

- (void)syncdWithDaemonConnection:(SNTXPCConnection *)daemonConn {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Create listener for return connection from daemon.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.listener = [[SNTXPCConnection alloc] initServerWithListener:listener];
  self.listener.exportedInterface = [SNTXPCSyncdInterface syncdInterface];
  self.listener.exportedObject = self.syncManager;
  self.listener.acceptedHandler = ^{
    LOGD(@"santad <--> santactl connections established");
    dispatch_semaphore_signal(sema);
  };
  self.listener.invalidationHandler = ^{
    // If santad is unloaded kill santactl
    LOGD(@"exiting");
    exit(0);
  };
  [self.listener resume];

  // Tell daemon to connect back to the above listener.
  [[daemonConn remoteObjectProxy] setSyncdListener:listener.endpoint];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self performSelectorInBackground:@selector(syncdWithDaemonConnection:) withObject:daemonConn];
  }

  [self.syncManager fullSyncSecondsFromNow:15];
}

@end
