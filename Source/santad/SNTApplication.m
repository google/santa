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

#import "SNTApplication.h"

#import <DiskArbitration/DiskArbitration.h>
#include <sys/stat.h>
#include <sys/types.h>

#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDaemonControlController.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
#import "SNTEventLog.h"
#import "SNTEventTable.h"
#import "SNTExecutionController.h"
#import "SNTFileWatcher.h"
#import "SNTLogging.h"
#import "SNTNotificationQueue.h"
#import "SNTRuleTable.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTApplication ()
@property DASessionRef diskArbSession;
@property SNTDriverManager *driverManager;
@property SNTEventLog *eventLog;
@property SNTExecutionController *execController;
@property SNTFileWatcher *configFileWatcher;
@property SNTXPCConnection *controlConnection;
@end

@implementation SNTApplication

- (instancetype)init {
  self = [super init];
  if (self) {
    // Locate and connect to driver
    _driverManager = [[SNTDriverManager alloc] init];

    if (!_driverManager) {
      LOGE(@"Failed to connect to driver, exiting.");
      return nil;
    }

    // Initialize tables
    SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];
    if (!ruleTable) {
      LOGE(@"Failed to initialize rule table.");
      return nil;
    }
    SNTEventTable *eventTable = [SNTDatabaseController eventTable];
    if (!eventTable) {
      LOGE(@"Failed to initialize event table.");
      return nil;
    }

    SNTNotificationQueue *notQueue = [[SNTNotificationQueue alloc] init];

    // Establish XPC listener for santactl connections
    SNTDaemonControlController *dc = [[SNTDaemonControlController alloc] init];
    dc.driverManager = _driverManager;
    dc.notQueue = notQueue;

    _controlConnection =
        [[SNTXPCConnection alloc] initServerWithName:[SNTXPCControlInterface serviceId]];
    _controlConnection.exportedInterface = [SNTXPCControlInterface controlInterface];
    _controlConnection.exportedObject = dc;
    [_controlConnection resume];

    __block SNTClientMode origMode = [[SNTConfigurator configurator] clientMode];
    _configFileWatcher = [[SNTFileWatcher alloc] initWithFilePath:kDefaultConfigFilePath handler:^{
      [[SNTConfigurator configurator] reloadConfigData];

      // Flush cache if client just went into lockdown.
      SNTClientMode newMode = [[SNTConfigurator configurator] clientMode];
      if (origMode != newMode) {
        origMode = newMode;
        if (newMode == SNTClientModeLockdown) {
          LOGI(@"Changed client mode, flushing cache.");
          [self.driverManager flushCache];
        }
      }

      // Ensure config file remains root:wheel 0644
      chown([kDefaultConfigFilePath fileSystemRepresentation], 0, 0);
      chmod([kDefaultConfigFilePath fileSystemRepresentation], 0644);
    }];

    _eventLog = [[SNTEventLog alloc] init];

    // Initialize the binary checker object
    _execController = [[SNTExecutionController alloc] initWithDriverManager:_driverManager
                                                                  ruleTable:ruleTable
                                                                 eventTable:eventTable
                                                              notifierQueue:notQueue
                                                                   eventLog:_eventLog];
    if (!_execController) return nil;
  }

  return self;
}

- (void)start {
  LOGI(@"Connected to driver, activating.");

  [self performSelectorInBackground:@selector(beginListeningForDecisionRequests) withObject:nil];
  [self performSelectorInBackground:@selector(beginListeningForLogRequests) withObject:nil];
  [self performSelectorInBackground:@selector(beginListeningForDiskMounts) withObject:nil];
}

- (void)beginListeningForDecisionRequests {
  dispatch_queue_t exec_queue = dispatch_queue_create(
      "com.google.santad.execution_queue", DISPATCH_QUEUE_CONCURRENT);
  dispatch_set_target_queue(exec_queue, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));

  [self.driverManager listenForDecisionRequests:^(santa_message_t message) {
    @autoreleasepool {
      switch (message.action) {
        case ACTION_REQUEST_SHUTDOWN: {
          LOGI(@"Driver requested a shutdown");
          exit(0);
        }
        case ACTION_REQUEST_BINARY: {
          dispatch_async(exec_queue, ^{
            [self.execController validateBinaryWithMessage:message];
          });
          break;
        }
        default: {
          LOGE(@"Received decision request without a valid action: %d", message.action);
          exit(1);
        }
      }
    }
  }];
}

- (void)beginListeningForLogRequests {
  dispatch_queue_t log_queue = dispatch_queue_create(
      "com.google.santad.log_queue", DISPATCH_QUEUE_CONCURRENT);
  dispatch_set_target_queue(
      log_queue, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));

  [self.driverManager listenForLogRequests:^(santa_message_t message) {
    @autoreleasepool {
      switch (message.action) {
        case ACTION_NOTIFY_DELETE:
        case ACTION_NOTIFY_EXCHANGE:
        case ACTION_NOTIFY_LINK:
        case ACTION_NOTIFY_RENAME:
        case ACTION_NOTIFY_WRITE: {
          dispatch_async(log_queue, ^{
            NSRegularExpression *re = [[SNTConfigurator configurator] fileChangesRegex];
            NSString *path = @(message.path);
            if ([re numberOfMatchesInString:path options:0 range:NSMakeRange(0, path.length)]) {
              [self.eventLog logFileModification:message];
            }
          });
          break;
        }
        case ACTION_NOTIFY_EXEC: {
          dispatch_async(log_queue, ^{
            [self.eventLog logAllowedExecution:message];
          });
          break;
        }
        default:
          LOGE(@"Received log request without a valid action: %d", message.action);
          break;
      }
    }
  }];
}

- (void)beginListeningForDiskMounts {
  dispatch_queue_t disk_queue = dispatch_queue_create(
      "com.google.santad.disk_queue", DISPATCH_QUEUE_SERIAL);

  _diskArbSession = DASessionCreate(NULL);
  DASessionSetDispatchQueue(_diskArbSession, disk_queue);

  DARegisterDiskAppearedCallback(
      _diskArbSession, NULL, diskAppearedCallback, (__bridge void *)self);
  DARegisterDiskDescriptionChangedCallback(
      _diskArbSession, NULL, NULL, diskDescriptionChangedCallback, (__bridge void *)self);
  DARegisterDiskDisappearedCallback(
      _diskArbSession, NULL, diskDisappearedCallback, (__bridge void *)self);
}

void diskAppearedCallback(DADiskRef disk, void *context) {
  SNTApplication *app = (__bridge SNTApplication *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  [app.eventLog logDiskAppeared:props];
}

void diskDescriptionChangedCallback(DADiskRef disk, CFArrayRef keys, void *context) {
  SNTApplication *app = (__bridge SNTApplication *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (props[@"DAVolumePath"]) [app.eventLog logDiskAppeared:props];
}

void diskDisappearedCallback(DADiskRef disk, void *context) {
  SNTApplication *app = (__bridge SNTApplication *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  [app.eventLog logDiskDisappeared:props];
}


@end
