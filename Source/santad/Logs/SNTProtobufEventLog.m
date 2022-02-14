/// Copyright 2021 Google Inc. All rights reserved.
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

#import "Source/santad/Logs/SNTProtobufEventLog.h"

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <libproc.h>
#import <os/log.h>

#import "Source/common/SNTAllowlistInfo.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/Santa.pbobjc.h"
#import "Source/santad/Logs/SNTSimpleMaildir.h"

@interface SNTProtobufEventLog ()
@property(readonly) id<SNTLogOutput> logOutput;
@end

@implementation SNTProtobufEventLog

- (instancetype)init {
  SNTSimpleMaildir *mailDir = [[SNTSimpleMaildir alloc]
                        initWithBaseDirectory:[[SNTConfigurator configurator] mailDirectory]
                               filenamePrefix:@"out.log"
                            fileSizeThreshold:[[SNTConfigurator configurator] mailDirectoryFileSizeThresholdKB] * 1024
                       directorySizeThreshold:[[SNTConfigurator configurator] mailDirectorySizeThresholdMB] * 1024 * 1024
                        maxTimeBetweenFlushes:[[SNTConfigurator configurator] mailDirectoryEventMaxFlushTimeSec]];
  return [self initWithLog:mailDir];
}

- (instancetype)initWithLog:(id<SNTLogOutput>)log {
  if (!_logOutput) {
    return nil;
  }

  self = [super init];
  if (self) {
    _logOutput = log;
  }
  return self;
}

- (void)forceFlush {
  [self.logOutput flush];
}

- (void)wrapMessageAndLog:(SNTLegacyMessage *)legacyMsg {
  SNTSantaMessage *sm = [[SNTSantaMessage alloc] init];
  sm.legacyMessage = legacyMsg;

  [self.logOutput logEvent:sm];
}

- (SNTLegacyFileModification_Action)protobufActionForSantaMessageAction:(santa_action_t)action {
  switch (action) {
    case ACTION_NOTIFY_DELETE:
      return SNTLegacyFileModification_Action_LegacyFileModificationActionDelete;
    case ACTION_NOTIFY_EXCHANGE:
      return SNTLegacyFileModification_Action_LegacyFileModificationActionExchange;
    case ACTION_NOTIFY_LINK:
      return SNTLegacyFileModification_Action_LegacyFileModificationActionLink;
    case ACTION_NOTIFY_RENAME:
      return SNTLegacyFileModification_Action_LegacyFileModificationActionRename;
    case ACTION_NOTIFY_WRITE:
      return SNTLegacyFileModification_Action_LegacyFileModificationActionWrite;
    default: return SNTLegacyFileModification_Action_LegacyFileModificationActionUnknown;
  }
}

- (NSString *)newpathForSantaMessage:(santa_message_t *)message {
  if (!message) {
    return nil;
  }

  switch (message->action) {
    case ACTION_NOTIFY_EXCHANGE:
    case ACTION_NOTIFY_LINK:
    case ACTION_NOTIFY_RENAME: return @(message->newpath);
    default: return nil;
  }
}

- (NSString *)processPathForSantaMessage:(santa_message_t *)message {
  if (!message) {
    return nil;
  }

  // If we have an ES message, use the path provided by the ES framework.
  // Otherwise, attempt to lookup the path. Note that this will fail if the
  // process being queried has already exited.
  if (message->es_message) {
    switch (message->action) {
      case ACTION_NOTIFY_DELETE:
      case ACTION_NOTIFY_EXCHANGE:
      case ACTION_NOTIFY_LINK:
      case ACTION_NOTIFY_RENAME:
      case ACTION_NOTIFY_WRITE: {
        return @(((es_message_t *)message->es_message)->process->executable->path.data);
      }
      default: return nil;
    }
  } else {
    char path[PATH_MAX];
    path[0] = '\0';
    proc_pidpath(message->pid, path, sizeof(path));
    return @(path);
  }
}

- (SNTLegacyProcessInfo *)protobufProcessInfoForSantaMessage:(santa_message_t *)message {
  if (!message) {
    return nil;
  }

  SNTLegacyProcessInfo *procInfo = [[SNTLegacyProcessInfo alloc] init];

  procInfo.pid = message->pid;
  procInfo.pidversion = message->pidversion;
  procInfo.ppid = message->ppid;
  procInfo.uid = message->uid;
  procInfo.gid = message->gid;

  procInfo.user = [self nameForUID:message->uid];
  procInfo.group = [self nameForGID:message->gid];

  return procInfo;
}

- (SNTLegacyExecution_Decision)protobufDecisionForCachedDecision:(SNTCachedDecision *)cd {
  if (cd.decision & SNTEventStateBlock) {
    return SNTLegacyExecution_Decision_LegacyExecutionDecisionDeny;
  } else if (cd.decision & SNTEventStateAllow) {
    return SNTLegacyExecution_Decision_LegacyExecutionDecisionAllow;
  } else {
    return SNTLegacyExecution_Decision_LegacyExecutionDecisionUnknown;
  }
}

- (SNTLegacyExecution_Reason)protobufReasonForCachedDecision:(SNTCachedDecision *)cd {
  switch (cd.decision) {
    case SNTEventStateAllowBinary: return SNTLegacyExecution_Reason_LegacyExecutionReasonBinary;
    case SNTEventStateAllowCompiler: return SNTLegacyExecution_Reason_LegacyExecutionReasonCompiler;
    case SNTEventStateAllowTransitive:
      return SNTLegacyExecution_Reason_LegacyExecutionReasonTransitive;
    case SNTEventStateAllowPendingTransitive:
      return SNTLegacyExecution_Reason_LegacyExecutionReasonPendingTransitive;
    case SNTEventStateAllowCertificate: return SNTLegacyExecution_Reason_LegacyExecutionReasonCert;
    case SNTEventStateAllowScope: return SNTLegacyExecution_Reason_LegacyExecutionReasonScope;
    case SNTEventStateAllowTeamID: return SNTLegacyExecution_Reason_LegacyExecutionReasonTeamId;
    case SNTEventStateAllowUnknown: return SNTLegacyExecution_Reason_LegacyExecutionReasonUnknown;
    case SNTEventStateBlockBinary: return SNTLegacyExecution_Reason_LegacyExecutionReasonBinary;
    case SNTEventStateBlockCertificate: return SNTLegacyExecution_Reason_LegacyExecutionReasonCert;
    case SNTEventStateBlockScope: return SNTLegacyExecution_Reason_LegacyExecutionReasonScope;
    case SNTEventStateBlockTeamID: return SNTLegacyExecution_Reason_LegacyExecutionReasonTeamId;
    case SNTEventStateBlockUnknown: return SNTLegacyExecution_Reason_LegacyExecutionReasonUnknown;

    case SNTEventStateAllow:
    case SNTEventStateUnknown:
    case SNTEventStateBundleBinary:
    case SNTEventStateBlock: return SNTLegacyExecution_Reason_LegacyExecutionReasonNotRunning;
  }

  return SNTLegacyExecution_Reason_LegacyExecutionReasonUnknown;
}

- (SNTLegacyExecution_Mode)protobufModeForClientMode:(SNTClientMode)mode {
  switch (mode) {
    case SNTClientModeMonitor: return SNTLegacyExecution_Mode_LegacyExecutionModeMonitor;
    case SNTClientModeLockdown: return SNTLegacyExecution_Mode_LegacyExecutionModeLockdown;
    case SNTClientModeUnknown: return SNTLegacyExecution_Mode_LegacyExecutionModeUnknown;
  }
  return SNTLegacyExecution_Mode_LegacyExecutionModeUnknown;
}

- (void)logFileModification:(santa_message_t)message {
  SNTLegacyFileModification *fileMod = [[SNTLegacyFileModification alloc] init];

  fileMod.action = [self protobufActionForSantaMessageAction:message.action];
  fileMod.path = @(message.path);
  fileMod.newpath = [self newpathForSantaMessage:&message];
  fileMod.process = @(message.pname);
  fileMod.processPath = [self processPathForSantaMessage:&message];
  fileMod.processInfo = [self protobufProcessInfoForSantaMessage:&message];
  fileMod.machineId =
    [[SNTConfigurator configurator] enableMachineIDDecoration] ? self.machineID : nil;

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.fileModification = fileMod;

  [self wrapMessageAndLog:legacyMsg];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  SNTLegacyExecution *exec = [[SNTLegacyExecution alloc] init];
  exec.decision = [self protobufDecisionForCachedDecision:cd];
  exec.reason = [self protobufReasonForCachedDecision:cd];
  exec.explain = cd.decisionExtra;
  exec.sha256 = cd.sha256;
  exec.certSha256 = cd.certSHA256;
  exec.certCn = cd.certCommonName;
  exec.quarantineURL = cd.quarantineURL;
  exec.processInfo = [self protobufProcessInfoForSantaMessage:&message];
  exec.mode = [self protobufModeForClientMode:[[SNTConfigurator configurator] clientMode]];
  exec.path = @(message.path);
  exec.originalPath = [self originalPathForTranslocation:&message];
  exec.argsArray = [(__bridge NSArray *)message.args_array mutableCopy];
  exec.machineId =
    [[SNTConfigurator configurator] enableMachineIDDecoration] ? self.machineID : nil;

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.execution = exec;

  [self wrapMessageAndLog:legacyMsg];
}

- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message {
  [self logExecution:message withDecision:cd];
}

- (void)logAllowedExecution:(santa_message_t)message {
  SNTCachedDecision *cd = [self cachedDecisionForMessage:message];
  [self logExecution:message withDecision:cd];

  // We also reset the timestamp for transitive rules here, because it happens to be where we
  // have access to both the execution notification and the sha256 associated with rule.
  [self resetTimestampForCachedDecision:cd];
}

- (void)logDiskAppeared:(NSDictionary *)diskProperties {
  NSString *dmgPath = nil;
  NSString *serial = nil;
  if ([diskProperties[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmgPath = [self diskImageForDevice:diskProperties[@"DADevicePath"]];
  } else {
    serial = [self serialForDevice:diskProperties[@"DADevicePath"]];
    serial = [serial stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@", diskProperties[@"DADeviceVendor"] ?: @"",
                                               diskProperties[@"DADeviceModel"] ?: @""];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  NSString *appearanceDateString = [self.dateFormatter
    stringFromDate:[NSDate
                     dateWithTimeIntervalSinceReferenceDate:[diskProperties[@"DAAppearanceTime"]
                                                              doubleValue]]];

  SNTLegacyDiskAppeared *diskAppeared = [[SNTLegacyDiskAppeared alloc] init];
  diskAppeared.mount = [diskProperties[@"DAVolumePath"] path];
  diskAppeared.volume = diskProperties[@"DAVolumeName"];
  diskAppeared.bsdName = diskProperties[@"DAMediaBSDName"];
  diskAppeared.fs = diskProperties[@"DAVolumeKind"];
  diskAppeared.model = model;
  diskAppeared.serial = serial;
  diskAppeared.bus = diskProperties[@"DADeviceProtocol"];
  diskAppeared.dmgPath = dmgPath;
  diskAppeared.appearance = appearanceDateString;

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.diskAppeared = diskAppeared;

  [self wrapMessageAndLog:legacyMsg];
}

- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  SNTLegacyDiskDisappeared *diskDisappeared = [[SNTLegacyDiskDisappeared alloc] init];

  diskDisappeared.mount = [diskProperties[@"DAVolumePath"] path];
  diskDisappeared.volume = diskProperties[@"DAVolumeName"];
  diskDisappeared.bsdName = diskProperties[@"DAMediaBSDName"];

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.diskDisappeared = diskDisappeared;

  [self wrapMessageAndLog:legacyMsg];
}

- (void)logBundleHashingEvents:(NSArray<SNTStoredEvent *> *)events {
  for (SNTStoredEvent *event in events) {
    SNTLegacyBundle *bundle = [[SNTLegacyBundle alloc] init];

    bundle.sha256 = event.fileSHA256;
    bundle.bundleHash = event.fileBundleHash;
    bundle.bundleName = event.fileBundleName;
    bundle.bundleId = event.fileBundleID;
    bundle.bundlePath = event.fileBundlePath;
    bundle.path = event.filePath;

    SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
    legacyMsg.bundle = bundle;

    [self wrapMessageAndLog:legacyMsg];
  }
}

- (void)logFork:(santa_message_t)message {
  SNTLegacyFork *forkEvent = [[SNTLegacyFork alloc] init];

  forkEvent.processInfo = [self protobufProcessInfoForSantaMessage:&message];

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.fork = forkEvent;

  [self wrapMessageAndLog:legacyMsg];
}

- (void)logExit:(santa_message_t)message {
  SNTLegacyExit *exitEvent = [[SNTLegacyExit alloc] init];

  exitEvent.processInfo = [self protobufProcessInfoForSantaMessage:&message];

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.exit = exitEvent;

  [self wrapMessageAndLog:legacyMsg];
}

- (void)logAllowlist:(SNTAllowlistInfo *)allowlistInfo {
  SNTLegacyAllowlist *allowlistEvent = [[SNTLegacyAllowlist alloc] init];

  allowlistEvent.pid = allowlistInfo.pid;
  allowlistEvent.pidversion = allowlistInfo.pidversion;
  allowlistEvent.path = allowlistInfo.targetPath;
  allowlistEvent.sha256 = allowlistInfo.sha256;

  SNTLegacyMessage *legacyMsg = [[SNTLegacyMessage alloc] init];
  legacyMsg.allowlist = allowlistEvent;

  [self wrapMessageAndLog:legacyMsg];
}

@end
