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

#include <pwd.h>
#include <sys/types.h>

#import "SNTApplication.h"

#include "SNTCommonEnums.h"
#include "SNTLogging.h"

#import "SNTConfigurator.h"
#import "SNTDaemonControlController.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
#import "SNTEventTable.h"
#import "SNTExecutionController.h"
#import "SNTRuleTable.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"
#import "SNTXPCNotifierInterface.h"

@interface SNTApplication ()
@property SNTDriverManager *driverManager;
@property SNTEventTable *eventTable;
@property SNTExecutionController *execController;
@property SNTRuleTable *ruleTable;
@property SNTXPCConnection *controlConnection;
@property SNTXPCConnection *notifierConnection;
@end

@implementation SNTApplication

- (instancetype)init {
  self = [super init];
  if (self) {
    // Locate and connect to driver
    _driverManager = [[SNTDriverManager alloc] init];

    if (!_driverManager) {
      LOGE(@"Failed to connect to driver, exiting.");

      // TODO(rah): Consider trying to load the extension from within santad.
      return nil;
    }

    // Initialize tables
    _ruleTable = [SNTDatabaseController ruleTable];
    if (! _ruleTable) {
      LOGE(@"Failed to initialize rule table.");
      return nil;
    }

    _eventTable = [SNTDatabaseController eventTable];
    if (! _eventTable) {
      LOGE(@"Failed to initialize event table.");
      return nil;
    }

    // Establish XPC listener for GUI agent connections
    _notifierConnection =
        [[SNTXPCConnection alloc] initServerWithName:[SNTXPCNotifierInterface serviceId]];
    _notifierConnection.remoteInterface = [SNTXPCNotifierInterface notifierInterface];
    [_notifierConnection resume];

    // Establish XPC listener for santactl connections
    _controlConnection =
        [[SNTXPCConnection alloc] initServerWithName:[SNTXPCControlInterface serviceId]];
    _controlConnection.exportedInterface = [SNTXPCControlInterface controlInterface];
    _controlConnection.exportedObject =
        [[SNTDaemonControlController alloc] initWithDriverManager:_driverManager];
    [_controlConnection resume];

    // Get client mode and begin observing for updates
    SNTConfigurator *configurator = [SNTConfigurator configurator];
    santa_clientmode_t clientMode = [configurator clientMode];
    [configurator addObserver:self
                   forKeyPath:@"clientMode"
                      options:NSKeyValueObservingOptionNew
                      context:NULL];

    // Initialize the binary checker object
    _execController = [[SNTExecutionController alloc] initWithDriverManager:_driverManager
                                                                  ruleTable:_ruleTable
                                                                 eventTable:_eventTable
                                                              operatingMode:clientMode
                                                         notifierConnection:_notifierConnection];
    if (!_execController) return nil;
  }

  return self;
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqual:@"clientMode"]) {
    self.execController.operatingMode = [change[NSKeyValueChangeNewKey] intValue];
  }
}

- (void)run {
  LOGI(@"Connected to driver, activating.");

  dispatch_queue_t q = dispatch_queue_create("com.google.santad.driver_queue",
                                             DISPATCH_QUEUE_CONCURRENT);

  [self.driverManager listenWithBlock:^(santa_message_t message) {
      @autoreleasepool {
        switch (message.action) {
          case ACTION_REQUEST_SHUTDOWN: {
            LOGI(@"Driver requested a shutdown");
            // Sleep before exiting to give driver chance to ready itself
            exit(0);
          }
          case ACTION_REQUEST_CHECKBW: {
            // Validate the binary aynchronously on a concurrent queue so we don't
            // hold up other execution requests in the background.
            dispatch_async(q, ^{
                struct passwd *user = getpwuid(message.userId);
                NSString *userName;
                if (user) {
                  userName = @(user->pw_name);
                }

                [self.execController validateBinaryWithPath:@(message.path)
                                                   userName:userName
                                                        pid:@(message.pid)
                                                       ppid:@(message.ppid)
                                                    vnodeId:message.vnode_id];
            });
            break;
          }
          default: {
            LOGE(@"Received request without a valid action: %d", message.action);
            exit(1);
          }
        }
      }
  }];
}

@end
