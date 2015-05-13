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
#include <sys/stat.h>
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
#import "SNTFileWatcher.h"
#import "SNTRuleTable.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"
#import "SNTXPCNotifierInterface.h"

@interface SNTApplication ()
@property SNTDriverManager *driverManager;
@property SNTEventTable *eventTable;
@property SNTExecutionController *execController;
@property SNTFileWatcher *configFileWatcher;
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
    if (!_ruleTable) {
      LOGE(@"Failed to initialize rule table.");
      return nil;
    }

    _eventTable = [SNTDatabaseController eventTable];
    if (!_eventTable) {
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

    _configFileWatcher = [[SNTFileWatcher alloc] initWithFilePath:kDefaultConfigFilePath
                                                          handler:^{
        [[SNTConfigurator configurator] reloadConfigData];

        // Ensure config file remains root:wheel 0644
        chown([kDefaultConfigFilePath fileSystemRepresentation], 0, 0);
        chmod([kDefaultConfigFilePath fileSystemRepresentation], 0644);
    }];

    // Initialize the binary checker object
    _execController = [[SNTExecutionController alloc] initWithDriverManager:_driverManager
                                                                  ruleTable:_ruleTable
                                                                 eventTable:_eventTable
                                                         notifierConnection:_notifierConnection];
    if (!_execController) return nil;
  }

  return self;
}

- (void)run {
  LOGI(@"Connected to driver, activating.");

  // Create a concurrent queue to put requests on, then set its priority to high.
  dispatch_queue_t q =
      dispatch_queue_create("com.google.santad.driver_queue", DISPATCH_QUEUE_CONCURRENT);
  dispatch_set_target_queue(q, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));

  [self.driverManager listenWithBlock:^(santa_message_t message) {
      @autoreleasepool {
        switch (message.action) {
          case ACTION_REQUEST_SHUTDOWN: {
            LOGI(@"Driver requested a shutdown");
            exit(0);
          }
          case ACTION_NOTIFY_EXEC_ALLOW_NODAEMON:
          case ACTION_NOTIFY_EXEC_ALLOW_CACHED:
          case ACTION_NOTIFY_EXEC_DENY_CACHED: {
            // TODO(rah): Implement.
            break;
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
