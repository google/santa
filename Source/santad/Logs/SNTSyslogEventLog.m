/// Copyright 2018 Google Inc. All rights reserved.
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

#import "Source/santad/Logs/SNTSyslogEventLog.h"

#import <libproc.h>
#include <EndpointSecurity/EndpointSecurity.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"

@implementation SNTSyslogEventLog

- (void)logFileModification:(santa_message_t)message {
  NSString *action, *newpath;

  NSString *path = @(message.path);

  switch (message.action) {
    case ACTION_NOTIFY_DELETE: {
      action = @"DELETE";
      break;
    }
    case ACTION_NOTIFY_EXCHANGE: {
      action = @"EXCHANGE";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_LINK: {
      action = @"LINK";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_RENAME: {
      action = @"RENAME";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_WRITE: {
      action = @"WRITE";
      break;
    }
    default: action = @"UNKNOWN"; break;
  }

  // init the string with 2k capacity to avoid reallocs
  NSMutableString *outStr = [NSMutableString stringWithCapacity:2048];
  [outStr appendFormat:@"action=%@|path=%@", action, [self sanitizeString:path]];
  if (newpath) {
    [outStr appendFormat:@"|newpath=%@", [self sanitizeString:newpath]];
  }
  char ppath[PATH_MAX] = "(null)";
  proc_pidpath(message.pid, ppath, PATH_MAX);

  [outStr appendFormat:@"|pid=%d|ppid=%d|process=%s|processpath=%s|uid=%d|user=%@|gid=%d|group=%@",
      message.pid, message.ppid, message.pname, ppath,
      message.uid, [self nameForUID:message.uid],
      message.gid, [self nameForGID:message.gid]];

  if ([[SNTConfigurator configurator] enableMachineIDDecoration]) {
    [outStr appendFormat:@"|machineid=%@", self.machineID];
  }

  [self writeLog:outStr];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  NSString *d, *r;
  BOOL logArgs = NO;

  switch (cd.decision) {
    case SNTEventStateAllowBinary:
      d = @"ALLOW";
      r = @"BINARY";
      logArgs = YES;
      break;
    case SNTEventStateAllowCompiler:
      d = @"ALLOW";
      r = @"COMPILER";
      logArgs = YES;
      break;
    case SNTEventStateAllowTransitive:
      d = @"ALLOW";
      r = @"TRANSITIVE";
      logArgs = YES;
      break;
    case SNTEventStateAllowPendingTransitive:
      d = @"ALLOW";
      r = @"PENDING_TRANSITIVE";
      logArgs = YES;
      break;
    case SNTEventStateAllowCertificate:
      d = @"ALLOW";
      r = @"CERT";
      logArgs = YES;
      break;
    case SNTEventStateAllowScope:
      d = @"ALLOW";
      r = @"SCOPE";
      logArgs = YES;
      break;
    case SNTEventStateAllowUnknown:
      d = @"ALLOW";
      r = @"UNKNOWN";
      logArgs = YES;
      break;
    case SNTEventStateBlockBinary:
      d = @"DENY";
      r = @"BINARY";
      break;
    case SNTEventStateBlockCertificate:
      d = @"DENY";
      r = @"CERT";
      break;
    case SNTEventStateBlockScope:
      d = @"DENY";
      r = @"SCOPE";
      break;
    case SNTEventStateBlockUnknown:
      d = @"DENY";
      r = @"UNKNOWN";
      break;
    default:
      d = @"ALLOW";
      r = @"NOTRUNNING";
      logArgs = YES;
      break;
  }

  // init the string with 4k capacity to avoid reallocs
  NSMutableString *outLog = [[NSMutableString alloc] initWithCapacity:4096];
  [outLog appendFormat:@"action=EXEC|decision=%@|reason=%@", d, r];

  if (cd.decisionExtra) {
    [outLog appendFormat:@"|explain=%@", cd.decisionExtra];
  }

  [outLog appendFormat:@"|sha256=%@", cd.sha256];

  if (cd.certSHA256) {
    [outLog appendFormat:@"|cert_sha256=%@|cert_cn=%@", cd.certSHA256,
     [self sanitizeString:cd.certCommonName]];
  }

  if (cd.quarantineURL) {
    [outLog appendFormat:@"|quarantine_url=%@", [self sanitizeString:cd.quarantineURL]];
  }

  NSString *mode;
  switch ([[SNTConfigurator configurator] clientMode]) {
    case SNTClientModeMonitor:
      mode = @"M"; break;
    case SNTClientModeLockdown:
      mode = @"L"; break;
    default:
      mode = @"U"; break;
  }

  [outLog appendFormat:@"|pid=%d|ppid=%d|uid=%d|user=%@|gid=%d|group=%@|mode=%@|path=%@",
      message.pid, message.ppid,
      message.uid, [self nameForUID:message.uid],
      message.gid, [self nameForGID:message.gid],
      mode, [self sanitizeString:@(message.path)]];

  // Check for app translocation by GateKeeper, and log original path if the case.
  NSString *originalPath = [self originalPathForTranslocation:message];
  if (originalPath) {
    [outLog appendFormat:@"|origpath=%@", [self sanitizeString:originalPath]];
  }

  if (logArgs) {
    if (@available(macOS 10.15, *)) {
      es_message_t *m = (es_message_t *)message.es_message;

      // TODO(rah): Profile this, it might need to be improved.
      uint32_t argCount = es_exec_arg_count(&(m->event.exec));
      NSMutableArray *args = [NSMutableArray arrayWithCapacity:argCount];
      for (int i = 0; i < argCount; ++i) {
        es_string_token_t arg = es_exec_arg(&(m->event.exec), i);
        [args addObject:[[NSString alloc] initWithBytes:arg.data
                                                 length:arg.length
                                               encoding:NSUTF8StringEncoding]];
      }
      [outLog appendFormat:@"|args=%@", [args componentsJoinedByString:@" "]];
    } else {
      [self addArgsForPid:message.pid toString:outLog];
    }
  }

  if ([[SNTConfigurator configurator] enableMachineIDDecoration]) {
    [outLog appendFormat:@"|machineid=%@", self.machineID];
  }

  [self writeLog:outLog];
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
  NSString *dmgPath = @"";
  NSString *serial = @"";
  if ([diskProperties[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmgPath = [self diskImageForDevice:diskProperties[@"DADevicePath"]];
  } else {
    serial = [self serialForDevice:diskProperties[@"DADevicePath"]];
    serial = [serial stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@",
                        diskProperties[@"DADeviceVendor"] ?: @"",
                        diskProperties[@"DADeviceModel"] ?: @""];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  double a = [diskProperties[@"DAAppearanceTime"] doubleValue];
  NSString *appearanceDateString =
      [self.dateFormatter stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:a]];

  NSString *format =
      @"action=DISKAPPEAR|mount=%@|volume=%@|bsdname=%@|fs=%@|"
      @"model=%@|serial=%@|bus=%@|dmgpath=%@|appearance=%@";
  NSString *outLog = [NSMutableString stringWithFormat:format,
                         [diskProperties[@"DAVolumePath"] path] ?: @"",
                         diskProperties[@"DAVolumeName"] ?: @"",
                         diskProperties[@"DAMediaBSDName"] ?: @"",
                         diskProperties[@"DAVolumeKind"] ?: @"",
                         model ?: @"",
                         serial,
                         diskProperties[@"DADeviceProtocol"] ?: @"",
                         dmgPath,
                         appearanceDateString];
  [self writeLog:outLog];
}

- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  NSString *format = @"action=DISKDISAPPEAR|mount=%@|volume=%@|bsdname=%@";
  NSString *outLog = [NSMutableString stringWithFormat:format,
                         [diskProperties[@"DAVolumePath"] path] ?: @"",
                         diskProperties[@"DAVolumeName"] ?: @"",
                         diskProperties[@"DAMediaBSDName"]];
  [self writeLog:outLog];
}

- (void)logBundleHashingEvents:(NSArray<SNTStoredEvent *> *)events {
  for (SNTStoredEvent *event in events) {
    NSString *format = @"action=BUNDLE|sha256=%@|bundlehash=%@|bundlename=%@|bundleid=%@|bundlepath=%@|path=%@";
    NSString *outLog = [NSMutableString stringWithFormat:format,
                           event.fileSHA256,
                           event.fileBundleHash,
                           event.fileBundleName,
                           event.fileBundleID,
                           event.fileBundlePath,
                           event.filePath];
    [self writeLog:outLog];
  }
}

- (void)writeLog:(NSString *)log {
  LOGI(@"%@", log);
}

@end
