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

- (void)wrapMessageAndLog:(void(^)(SNTPBSantaMessage*))setMessage {
  SNTPBSantaMessage *sm = [[SNTPBSantaMessage alloc] init];
  setMessage(sm);

  [self.logOutput logEvent:sm];
}

- (SNTPBFileModification_Action)protobufActionForSantaMessageAction:(santa_action_t)action {
  switch (action) {
    case ACTION_NOTIFY_DELETE:
      return SNTPBFileModification_Action_FileModificationActionDelete;
    case ACTION_NOTIFY_EXCHANGE:
      return SNTPBFileModification_Action_FileModificationActionExchange;
    case ACTION_NOTIFY_LINK:
      return SNTPBFileModification_Action_FileModificationActionLink;
    case ACTION_NOTIFY_RENAME:
      return SNTPBFileModification_Action_FileModificationActionRename;
    case ACTION_NOTIFY_WRITE:
      return SNTPBFileModification_Action_FileModificationActionWrite;
    default: return SNTPBFileModification_Action_FileModificationActionUnknown;
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

- (SNTPBProcessInfo *)protobufProcessInfoForSantaMessage:(santa_message_t *)message {
  if (!message) {
    return nil;
  }

  SNTPBProcessInfo *procInfo = [[SNTPBProcessInfo alloc] init];

  procInfo.pid = message->pid;
  procInfo.pidversion = message->pidversion;
  procInfo.ppid = message->ppid;
  procInfo.uid = message->uid;
  procInfo.gid = message->gid;

  procInfo.user = [self nameForUID:message->uid];
  procInfo.group = [self nameForGID:message->gid];

  return procInfo;
}

- (SNTPBExecution_Decision)protobufDecisionForCachedDecision:(SNTCachedDecision *)cd {
  if (cd.decision & SNTEventStateBlock) {
    return SNTPBExecution_Decision_ExecutionDecisionDeny;
  } else if (cd.decision & SNTEventStateAllow) {
    return SNTPBExecution_Decision_ExecutionDecisionAllow;
  } else {
    return SNTPBExecution_Decision_ExecutionDecisionUnknown;
  }
}

- (SNTPBExecution_Reason)protobufReasonForCachedDecision:(SNTCachedDecision *)cd {
  switch (cd.decision) {
    case SNTEventStateAllowBinary: return SNTPBExecution_Reason_ExecutionReasonBinary;
    case SNTEventStateAllowCompiler: return SNTPBExecution_Reason_ExecutionReasonCompiler;
    case SNTEventStateAllowTransitive:
      return SNTPBExecution_Reason_ExecutionReasonTransitive;
    case SNTEventStateAllowPendingTransitive:
      return SNTPBExecution_Reason_ExecutionReasonPendingTransitive;
    case SNTEventStateAllowCertificate: return SNTPBExecution_Reason_ExecutionReasonCert;
    case SNTEventStateAllowScope: return SNTPBExecution_Reason_ExecutionReasonScope;
    case SNTEventStateAllowTeamID: return SNTPBExecution_Reason_ExecutionReasonTeamId;
    case SNTEventStateAllowUnknown: return SNTPBExecution_Reason_ExecutionReasonUnknown;
    case SNTEventStateBlockBinary: return SNTPBExecution_Reason_ExecutionReasonBinary;
    case SNTEventStateBlockCertificate: return SNTPBExecution_Reason_ExecutionReasonCert;
    case SNTEventStateBlockScope: return SNTPBExecution_Reason_ExecutionReasonScope;
    case SNTEventStateBlockTeamID: return SNTPBExecution_Reason_ExecutionReasonTeamId;
    case SNTEventStateBlockUnknown: return SNTPBExecution_Reason_ExecutionReasonUnknown;

    case SNTEventStateAllow:
    case SNTEventStateUnknown:
    case SNTEventStateBundleBinary:
    case SNTEventStateBlock: return SNTPBExecution_Reason_ExecutionReasonNotRunning;
  }

  return SNTPBExecution_Reason_ExecutionReasonUnknown;
}

- (SNTPBExecution_Mode)protobufModeForClientMode:(SNTClientMode)mode {
  switch (mode) {
    case SNTClientModeMonitor: return SNTPBExecution_Mode_ExecutionModeMonitor;
    case SNTClientModeLockdown: return SNTPBExecution_Mode_ExecutionModeLockdown;
    case SNTClientModeUnknown: return SNTPBExecution_Mode_ExecutionModeUnknown;
  }
  return SNTPBExecution_Mode_ExecutionModeUnknown;
}

- (void)logFileModification:(santa_message_t)message {
  SNTPBFileModification *fileMod = [[SNTPBFileModification alloc] init];

  fileMod.action = [self protobufActionForSantaMessageAction:message.action];
  fileMod.path = @(message.path);
  fileMod.newpath = [self newpathForSantaMessage:&message];
  fileMod.process = @(message.pname);
  fileMod.processPath = [self processPathForSantaMessage:&message];
  fileMod.processInfo = [self protobufProcessInfoForSantaMessage:&message];
  fileMod.machineId =
    [[SNTConfigurator configurator] enableMachineIDDecoration] ? self.machineID : nil;

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.fileModification = fileMod;
  }];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  SNTPBExecution *exec = [[SNTPBExecution alloc] init];
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

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.execution = exec;
  }];
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

  SNTPBDiskAppeared *diskAppeared = [[SNTPBDiskAppeared alloc] init];
  diskAppeared.mount = [diskProperties[@"DAVolumePath"] path];
  diskAppeared.volume = diskProperties[@"DAVolumeName"];
  diskAppeared.bsdName = diskProperties[@"DAMediaBSDName"];
  diskAppeared.fs = diskProperties[@"DAVolumeKind"];
  diskAppeared.model = model;
  diskAppeared.serial = serial;
  diskAppeared.bus = diskProperties[@"DADeviceProtocol"];
  diskAppeared.dmgPath = dmgPath;
  diskAppeared.appearance = appearanceDateString;

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.diskAppeared = diskAppeared;
  }];
}

- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  SNTPBDiskDisappeared *diskDisappeared = [[SNTPBDiskDisappeared alloc] init];

  diskDisappeared.mount = [diskProperties[@"DAVolumePath"] path];
  diskDisappeared.volume = diskProperties[@"DAVolumeName"];
  diskDisappeared.bsdName = diskProperties[@"DAMediaBSDName"];

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.diskDisappeared = diskDisappeared;
  }];
}

- (void)logBundleHashingEvents:(NSArray<SNTStoredEvent *> *)events {
  for (SNTStoredEvent *event in events) {
    SNTPBBundle *bundle = [[SNTPBBundle alloc] init];

    bundle.sha256 = event.fileSHA256;
    bundle.bundleHash = event.fileBundleHash;
    bundle.bundleName = event.fileBundleName;
    bundle.bundleId = event.fileBundleID;
    bundle.bundlePath = event.fileBundlePath;
    bundle.path = event.filePath;

    [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
      sm.bundle = bundle;
    }];
  }
}

- (void)logFork:(santa_message_t)message {
  SNTPBFork *forkEvent = [[SNTPBFork alloc] init];

  forkEvent.processInfo = [self protobufProcessInfoForSantaMessage:&message];

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.fork = forkEvent;
  }];
}

- (void)logExit:(santa_message_t)message {
  SNTPBExit *exitEvent = [[SNTPBExit alloc] init];

  exitEvent.processInfo = [self protobufProcessInfoForSantaMessage:&message];

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.exit = exitEvent;
  }];
}

- (void)logAllowlist:(SNTAllowlistInfo *)allowlistInfo {
  SNTPBAllowlist *allowlistEvent = [[SNTPBAllowlist alloc] init];

  allowlistEvent.pid = allowlistInfo.pid;
  allowlistEvent.pidversion = allowlistInfo.pidversion;
  allowlistEvent.path = allowlistInfo.targetPath;
  allowlistEvent.sha256 = allowlistInfo.sha256;

  [self wrapMessageAndLog:^(SNTPBSantaMessage*sm) {
    sm.allowlist = allowlistEvent;
  }];
}

@end
