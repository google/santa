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

#import "Source/santad/SNTApplication.h"
#import "Source/santad/SNTApplicationCoreMetrics.h"

#import <DiskArbitration/DiskArbitration.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCMetricServiceInterface.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCUnprivilegedControlInterface.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/EventProviders/SNTCachingEndpointSecurityManager.h"
#import "Source/santad/EventProviders/SNTDriverManager.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityManager.h"
#import "Source/santad/EventProviders/SNTEventProvider.h"
#import "Source/santad/Logs/SNTEventLog.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTDaemonControlController.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"

@interface SNTApplication ()
@property DASessionRef diskArbSession;
@property id<SNTEventProvider> eventProvider;
@property SNTExecutionController *execController;
@property SNTCompilerController *compilerController;
@property MOLXPCConnection *controlConnection;
@property SNTNotificationQueue *notQueue;
@property pid_t syncdPID;
@property MOLXPCConnection *metricsConnection;
@property dispatch_source_t metricsTimer;
@end

@implementation SNTApplication

- (instancetype)init {
  self = [super init];
  if (self) {
    SNTConfigurator *configurator = [SNTConfigurator configurator];

    // Choose an event logger.
    // Locate and connect to driver / SystemExtension
    if ([configurator enableSystemExtension]) {
      if ([configurator enableSysxCache]) {
        LOGI(@"Using CachingEndpointSecurity as event provider.");
        _eventProvider = [[SNTCachingEndpointSecurityManager alloc] init];
      } else {
        LOGI(@"Using EndpointSecurity as event provider.");
        _eventProvider = [[SNTEndpointSecurityManager alloc] init];
      }
    } else {
      LOGI(@"Using Kauth as event provider.");
      _eventProvider = [[SNTDriverManager alloc] init];
    }

    if (!_eventProvider) {
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

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
      // The filter is reset when santad disconnects from the driver.
      // Add the default filters.
      [self.eventProvider fileModificationPrefixFilterAdd:@[ @"/.", @"/dev/" ]];

      // TODO(bur): Add KVO handling for fileChangesPrefixFilters.
      [self.eventProvider fileModificationPrefixFilterAdd:[configurator fileChangesPrefixFilters]];
    });

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
                   forKeyPath:NSStringFromSelector(@selector(allowedPathRegex))
                      options:bits
                      context:NULL];
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(blockedPathRegex))
                      options:bits
                      context:NULL];
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(exportMetrics))
                      options:bits
                      context:NULL];
    [configurator addObserver:self
                   forKeyPath:NSStringFromSelector(@selector(metricExportInterval))
                      options:bits
                      context:NULL];

    if (![configurator enableSystemExtension]) {
      [configurator addObserver:self
                     forKeyPath:NSStringFromSelector(@selector(enableSystemExtension))
                        options:bits
                        context:NULL];
    }

    // Establish XPC listener for Santa and santactl connections
    SNTDaemonControlController *dc =
      [[SNTDaemonControlController alloc] initWithEventProvider:_eventProvider
                                              notificationQueue:self.notQueue
                                                     syncdQueue:syncdQueue];

    _controlConnection =
      [[MOLXPCConnection alloc] initServerWithName:[SNTXPCControlInterface serviceID]];
    _controlConnection.privilegedInterface = [SNTXPCControlInterface controlInterface];
    _controlConnection.unprivilegedInterface =
      [SNTXPCUnprivilegedControlInterface controlInterface];
    _controlConnection.exportedObject = dc;
    [_controlConnection resume];

    // Initialize the transitive whitelisting controller object.
    _compilerController = [[SNTCompilerController alloc] initWithEventProvider:_eventProvider];

    // Initialize the binary checker object
    _execController = [[SNTExecutionController alloc] initWithEventProvider:_eventProvider
                                                                  ruleTable:ruleTable
                                                                 eventTable:eventTable
                                                              notifierQueue:self.notQueue
                                                                 syncdQueue:syncdQueue];
    // Start up santactl as a daemon if a sync server exists.
    [self startSyncd];

    if (!_execController) return nil;

    if ([configurator exportMetrics]) {
      [self startMetricsPoll];
    }
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
  [self.eventProvider listenForDecisionRequests:^(santa_message_t message) {
    switch (message.action) {
      case ACTION_REQUEST_SHUTDOWN: {
        LOGI(@"Driver requested a shutdown");
        exit(0);
      }
      case ACTION_REQUEST_BINARY: {
        [self->_execController validateBinaryWithMessage:message];
        break;
      }
      case ACTION_NOTIFY_WHITELIST: {
        // Determine if we should add a transitive whitelisting rule for this new file.
        // Requires that writing process was a compiler and that new file is executable.
        [self.compilerController createTransitiveRule:message];
        break;
      }
      default: {
        LOGE(@"Received decision request without a valid action: %d", message.action);
        exit(1);
      }
    }
  }];
}

- (void)beginListeningForLogRequests {
  [self.eventProvider listenForLogRequests:^(santa_message_t message) {
    switch (message.action) {
      case ACTION_NOTIFY_DELETE:
      case ACTION_NOTIFY_EXCHANGE:
      case ACTION_NOTIFY_LINK:
      case ACTION_NOTIFY_RENAME:
      case ACTION_NOTIFY_WRITE: {
        NSRegularExpression *re = [[SNTConfigurator configurator] fileChangesRegex];
        NSString *path = @(message.path);
        if (!path) break;
        if ([re numberOfMatchesInString:path options:0 range:NSMakeRange(0, path.length)]) {
          [[SNTEventLog logger] logFileModification:message];
        }
        break;
      }
      case ACTION_NOTIFY_EXEC: {
        [[SNTEventLog logger] logAllowedExecution:message];
        break;
      }
      case ACTION_NOTIFY_FORK: [[SNTEventLog logger] logFork:message]; break;
      case ACTION_NOTIFY_EXIT: [[SNTEventLog logger] logExit:message]; break;
      default: LOGE(@"Received log request without a valid action: %d", message.action); break;
    }
  }];
}

- (void)beginListeningForDiskMounts {
  dispatch_queue_t disk_queue =
    dispatch_queue_create("com.google.santad.disk_queue", DISPATCH_QUEUE_SERIAL);

  _diskArbSession = DASessionCreate(NULL);
  DASessionSetDispatchQueue(_diskArbSession, disk_queue);

  DARegisterDiskAppearedCallback(_diskArbSession, NULL, diskAppearedCallback,
                                 (__bridge void *)self);
  DARegisterDiskDescriptionChangedCallback(_diskArbSession, NULL, NULL,
                                           diskDescriptionChangedCallback, (__bridge void *)self);
  DARegisterDiskDisappearedCallback(_diskArbSession, NULL, diskDisappearedCallback,
                                    (__bridge void *)self);
}

void diskAppearedCallback(DADiskRef disk, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  [[SNTEventLog logger] logDiskAppeared:props];
}

void diskDescriptionChangedCallback(DADiskRef disk, CFArrayRef keys, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  if (props[@"DAVolumePath"]) [[SNTEventLog logger] logDiskAppeared:props];
}

void diskDisappearedCallback(DADiskRef disk, void *context) {
  SNTApplication *app = (__bridge SNTApplication *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  [[SNTEventLog logger] logDiskDisappeared:props];
  [app.eventProvider flushCacheNonRootOnly:YES];
}

// Taken from Apple's Concurrency Programming Guide.
dispatch_source_t createDispatchTimer(uint64_t interval, uint64_t leeway, dispatch_queue_t queue,
                                      dispatch_block_t block) {
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

  if (timer) {
    dispatch_source_set_timer(timer, dispatch_walltime(NULL, 0), interval, leeway);
    dispatch_source_set_event_handler(timer, block);
    dispatch_resume(timer);
  }

  return timer;
}

/*
 * Create a SNTMetricSet instance and start reporting essential metrics immediately to the metric
 * service.
 */
- (void)startMetricsPoll {
  NSUInteger interval = [[SNTConfigurator configurator] metricExportInterval];

  LOGI(@"starting to export metrics every %ld seconds", interval);
  void (^exportMetricsBlock)(void) = ^{
    [[self.metricsConnection remoteObjectProxy]
      exportForMonitoring:[[SNTMetricSet sharedInstance] export]];
  };

  static dispatch_once_t registerMetrics;

  dispatch_once(&registerMetrics, ^{
    _metricsConnection = [SNTXPCMetricServiceInterface configuredConnection];
    [_metricsConnection resume];

    LOGD(@"registering core metrics");
    SNTRegisterCoreMetrics();
    exportMetricsBlock();
  });

  dispatch_source_t timer = createDispatchTimer(interval * NSEC_PER_SEC, 1ull * NSEC_PER_SEC,
                                                dispatch_get_main_queue(), exportMetricsBlock);
  if (!timer) {
    LOGE(@"failed to created timer for exporting metrics");
    return;
  }

  _metricsTimer = timer;
}

- (void)stopMetricsPoll {
  if (!_metricsTimer) {
    LOGE(@"stopMetricsPoll called while _metricsTimer is nil");
    return;
  }

  dispatch_source_cancel(_metricsTimer);
}

- (void)startSyncd {
  if (![[SNTConfigurator configurator] syncBaseURL]) return;
  [self stopSyncd];
  self.syncdPID = fork();
  if (self.syncdPID == -1) {
    LOGI(@"Failed to fork");
    self.syncdPID = 0;
  } else if (self.syncdPID == 0) {
    // The santactl executable will drop privileges just after the XPC
    // connection has been estabilished; this is done this way so that
    // the XPC authentication can occur
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
                        change:(NSDictionary<NSString *, id> *)change
                       context:(void *)context {
  NSString *newKey = NSKeyValueChangeNewKey;
  NSString *oldKey = NSKeyValueChangeOldKey;
  if ([keyPath isEqualToString:NSStringFromSelector(@selector(clientMode))]) {
    SNTClientMode new =
      [ change[newKey] isKindOfClass : [NSNumber class] ] ? [ change[newKey] longLongValue ] : 0;
    SNTClientMode old =
      [change[oldKey] isKindOfClass:[NSNumber class]] ? [change[oldKey] longLongValue] : 0;
    if (new != old) [self clientModeDidChange:new];
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(syncBaseURL))]) {
    NSURL *new = [ change[newKey] isKindOfClass : [NSURL class] ] ? change[newKey] : nil;
    NSURL *old = [change[oldKey] isKindOfClass:[NSURL class]] ? change[oldKey] : nil;
    if (!new && !old) return;
    if (![new.absoluteString isEqualToString:old.absoluteString]) [self syncBaseURLDidChange:new];
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(allowedPathRegex))] ||
             [keyPath isEqualToString:NSStringFromSelector(@selector(blockedPathRegex))]) {
    NSRegularExpression *new =
      [ change[newKey] isKindOfClass : [NSRegularExpression class] ] ? change[newKey] : nil;
    NSRegularExpression *old =
      [change[oldKey] isKindOfClass:[NSRegularExpression class]] ? change[oldKey] : nil;
    if (!new && !old) return;
    if (![new.pattern isEqualToString:old.pattern]) {
      LOGI(@"Changed [allow|deny]list regex, flushing cache");
      [self.eventProvider flushCacheNonRootOnly:NO];
    }
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(enableSystemExtension))]) {
    BOOL new =
      [ change[newKey] isKindOfClass : [NSNumber class] ] ? [ change[newKey] boolValue ] : NO;
    BOOL old = [change[oldKey] isKindOfClass:[NSNumber class]] ? [change[oldKey] boolValue] : NO;
    if (old == NO && new == YES) {
      LOGI(@"EnableSystemExtension changed NO -> YES");
      LOGI(@"The penultimate exit.");
      exit(0);
    }
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(exportMetrics))]) {
    BOOL new = [ change[newKey] boolValue ];
    BOOL old = [change[oldKey] boolValue];

    if (old == NO && new == YES) {
      LOGI(@"metricsExport changed NO -> YES, starting to export metrics");
      [self startMetricsPoll];
    } else if (old == YES && new == NO) {
      LOGI(@"metricsExport changed YES -> NO, stopping export of metrics");
      [self stopMetricsPoll];
    }
  } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(metricExportInterval))]) {
    // clang-format off
    NSUInteger new = [ change[newKey] unsignedIntegerValue ];
    NSUInteger old = [ change[oldKey] unsignedIntegerValue ];
    // clang-format on

    LOGI(@"MetricExportInterval changed from %ld to %ld restarting export", old, new);

    [self stopMetricsPoll];
    [self startMetricsPoll];
  }
}

- (void)clientModeDidChange:(SNTClientMode)clientMode {
  if (clientMode == SNTClientModeLockdown) {
    LOGI(@"Changed client mode, flushing cache.");
    [self.eventProvider flushCacheNonRootOnly:NO];
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
