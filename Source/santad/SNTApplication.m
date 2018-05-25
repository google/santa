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

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDaemonControlController.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
#import "SNTDropRootPrivs.h"
#import "SNTEventTable.h"
#import "SNTExecutionController.h"
#import "SNTFileEventLog.h"
#import "SNTLogging.h"
#import "SNTNotificationQueue.h"
#import "SNTRuleTable.h"
#import "SNTSyncdQueue.h"
#import "SNTSyslogEventLog.h"
#import "SNTXPCControlInterface.h"
#import "SNTXPCNotifierInterface.h"

@interface SNTApplication ()
@property DASessionRef diskArbSession;
@property SNTDriverManager *driverManager;
@property SNTEventLog *eventLog;
@property SNTExecutionController *execController;
@property MOLXPCConnection *controlConnection;
@property SNTNotificationQueue *notQueue;
@property pid_t syncdPID;
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

    // Choose an event logger.
    SNTConfigurator *configurator = [SNTConfigurator configurator];
    switch ([configurator eventLogType]) {
      case SNTEventLogTypeSyslog:
        _eventLog = [[SNTSyslogEventLog alloc] init];
        break;
      case SNTEventLogTypeFilelog:
        _eventLog = [[SNTFileEventLog alloc] init];
        break;
    }

    self.notQueue = [[SNTNotificationQueue alloc] init];
    SNTSyncdQueue *syncdQueue = [[SNTSyncdQueue alloc] init];

    // Restart santactl if it goes down
    syncdQueue.invalidationHandler = ^{
      [self startSyncd];
    };

    // Listen for actionable config changes.
    NSKeyValueObservingOptions bits = (NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld);
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(clientMode))
                      options:bits
                      context:NULL];
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(syncBaseURL))
                      options:bits
                      context:NULL];
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(whitelistPathRegex))
                      options:bits
                      context:NULL];
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(blacklistPathRegex))
                      options:bits
                      context:NULL];

    // Establish XPC listener for Santa and santactl connections
    SNTDaemonControlController *dc =
        [[SNTDaemonControlController alloc] initWithDriverManager:_driverManager
                                                notificationQueue:self.notQueue
                                                       syncdQueue:syncdQueue
                                                         eventLog:_eventLog];

    _controlConnection =
        [[MOLXPCConnection alloc] initServerWithName:[SNTXPCControlInterface serviceId]];
    _controlConnection.exportedInterface = [SNTXPCControlInterface controlInterface];
    _controlConnection.exportedObject = dc;
    [_controlConnection resume];

    // Initialize the binary checker object
    _execController = [[SNTExecutionController alloc] initWithDriverManager:_driverManager
                                                                  ruleTable:ruleTable
                                                                 eventTable:eventTable
                                                              notifierQueue:self.notQueue
                                                                 syncdQueue:syncdQueue
                                                                   eventLog:_eventLog];
    // Start up santactl as a daemon if a sync server exists.
    [self startSyncd];

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
  dispatch_set_target_queue(
      exec_queue, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));

  [self.driverManager listenForDecisionRequests:^(santa_message_t message) {
    @autoreleasepool {
      dispatch_async(exec_queue, ^{
        switch (message.action) {
          case ACTION_REQUEST_SHUTDOWN: {
            LOGI(@"Driver requested a shutdown");
            exit(0);
          }
          case ACTION_REQUEST_BINARY: {
            [_execController validateBinaryWithMessage:message];
            break;
          }
          default: {
            LOGE(@"Received decision request without a valid action: %d", message.action);
            exit(1);
          }
        }
      });
    }
  }];
}

- (void)beginListeningForLogRequests {
  dispatch_queue_t log_queue = dispatch_queue_create(
      "com.google.santad.log_queue", DISPATCH_QUEUE_CONCURRENT);
  dispatch_set_target_queue(
      log_queue, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));

  // Limit number of threads the queue can create.
  dispatch_semaphore_t concurrencyLimiter = dispatch_semaphore_create(15);

  [self.driverManager listenForLogRequests:^(santa_message_t message) {
    @autoreleasepool {
      dispatch_semaphore_wait(concurrencyLimiter, DISPATCH_TIME_FOREVER);
      dispatch_async(log_queue, ^{
        switch (message.action) {
          case ACTION_NOTIFY_DELETE:
          case ACTION_NOTIFY_EXCHANGE:
          case ACTION_NOTIFY_LINK:
          case ACTION_NOTIFY_RENAME:
          case ACTION_NOTIFY_WRITE: {
            NSRegularExpression *re = [[SNTConfigurator configurator] fileChangesRegex];
            NSString *path = @(message.path);
            if ([re numberOfMatchesInString:path options:0 range:NSMakeRange(0, path.length)]) {
              [_eventLog logFileModification:message];
            }
            break;
          }
          case ACTION_NOTIFY_EXEC: {
            [_eventLog logAllowedExecution:message];
            break;
          }
          default:
            LOGE(@"Received log request without a valid action: %d", message.action);
            break;
        }
        dispatch_semaphore_signal(concurrencyLimiter);
      });
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
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  [app.eventLog logDiskAppeared:props];
}

void diskDescriptionChangedCallback(DADiskRef disk, CFArrayRef keys, void *context) {
  SNTApplication *app = (__bridge SNTApplication *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  if (props[@"DAVolumePath"]) [app.eventLog logDiskAppeared:props];
}

void diskDisappearedCallback(DADiskRef disk, void *context) {
  SNTApplication *app = (__bridge SNTApplication *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  [app.eventLog logDiskDisappeared:props];
  [app.driverManager flushCache];
}

- (void)startSyncd {
  if (![[SNTConfigurator configurator] syncBaseURL]) return;
  [self stopSyncd];
  self.syncdPID = fork();
  if (self.syncdPID == -1) {
    LOGI(@"Failed to fork");
    self.syncdPID = 0;
  } else if (self.syncdPID == 0) {
    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      _exit(EPERM);
    }
    _exit(execl(kSantaCtlPath, kSantaCtlPath, "sync", "--daemon", "--syslog", NULL));
  }
  LOGI(@"santactl started with pid: %i", self.syncdPID);
}

- (void)stopSyncd {
  if (!self.syncdPID) return;
  int ret = kill(self.syncdPID, SIGKILL);
  LOGD(@"kill(%i, 9) = %i", self.syncdPID, ret);
  self.syncdPID = 0;
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary<NSString *,id> *)change
                       context:(void *)context {
  NSString *newKey = NSKeyValueChangeNewKey;
  NSString *oldKey = NSKeyValueChangeOldKey;
  if ([keyPath isEqualToString:NSStringFromSelector(@selector(clientMode))]) {
    SNTClientMode new =
        [change[newKey] isKindOfClass:[NSNumber class]] ? [change[newKey] longLongValue] : 0;
    SNTClientMode old =
        [change[oldKey] isKindOfClass:[NSNumber class]] ? [change[oldKey] longLongValue] : 0;
    if (new != old) [self clientModeDidChange:new];
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(syncBaseURL))]) {
    NSURL *new = [change[newKey] isKindOfClass:[NSURL class]] ? change[newKey] : nil;
    NSURL *old = [change[oldKey] isKindOfClass:[NSURL class]] ? change[oldKey] : nil;
    if (!new && !old) return;
    if (![new.absoluteString isEqualToString:old.absoluteString]) [self syncBaseURLDidChange:new];
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(whitelistPathRegex))] ||
             [keyPath isEqualToString:NSStringFromSelector(@selector(blacklistPathRegex))]) {
    NSRegularExpression *new =
        [change[newKey] isKindOfClass:[NSRegularExpression class]] ? change[newKey] : nil;
    NSRegularExpression *old =
        [change[oldKey] isKindOfClass:[NSRegularExpression class]] ? change[oldKey] : nil;
    if (!new && !old) return;
    if (![new.pattern isEqualToString:old.pattern]) {
      LOGI(@"Changed [white|black]list regex, flushing cache");
      [self.driverManager flushCache];
    }
  }
}

- (void)clientModeDidChange:(SNTClientMode)clientMode {
  if (clientMode == SNTClientModeLockdown) {
    LOGI(@"Changed client mode, flushing cache.");
    [self.driverManager flushCache];
  }
  [[self.notQueue.notifierConnection remoteObjectProxy] postClientModeNotification:clientMode];
}

- (void)syncBaseURLDidChange:(NSURL *)syncBaseURL {
  if (syncBaseURL) {
    LOGI(@"Starting santactl with new SyncBaseURL: %@", syncBaseURL);
    [NSObject cancelPreviousPerformRequestsWithTarget:[SNTConfigurator configurator]
                                             selector:@selector(clearSyncState)
                                               object:nil];
    [self startSyncd];
  } else {
    LOGI(@"SyncBaseURL removed, killing santactl pid: %i", self.syncdPID);
    [self stopSyncd];
    // Keep the syncState active for 10 min in case com.apple.ManagedClient is flapping.
    [[SNTConfigurator configurator] performSelector:@selector(clearSyncState)
                                         withObject:nil
                                         afterDelay:600];
  }
}

@end
