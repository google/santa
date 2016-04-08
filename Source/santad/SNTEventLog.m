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

#import "SNTEventLog.h"

#include <grp.h>
#include <libproc.h>
#include <pwd.h>
#include <sys/sysctl.h>

#import "MOLCertificate.h"
#import "SNTCachedDecision.h"
#import "SNTCommonEnums.h"
#import "SNTFileInfo.h"
#import "SNTKernelCommon.h"
#import "SNTLogging.h"

@interface SNTEventLog ()
@property NSMutableDictionary *detailStore;
@end

@implementation SNTEventLog

- (instancetype)init {
  self = [super init];
  if (self) {
    _detailStore = [NSMutableDictionary dictionaryWithCapacity:10000];
  }
  return self;
}

- (void)saveDecisionDetails:(SNTCachedDecision *)cd {
  self.detailStore[@(cd.vnodeId)] = cd;
}

- (void)logFileModification:(santa_message_t)message {
  NSString *action, *path, *newpath, *sha256, *outStr;

  path = @(message.path);

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
      SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:path];
      if (fileInfo.fileSize < 1024 * 1024) {
        sha256 = fileInfo.SHA256;
      } else {
        sha256 = @"(too large)";
      }
      break;
    }
    default: action = @"UNKNOWN"; break;
  }

  outStr = [NSString stringWithFormat:@"action=%@|path=%@", action, [self sanitizeString:path]];
  if (newpath) {
    outStr = [outStr stringByAppendingFormat:@"|newpath=%@", [self sanitizeString:newpath]];
  }
  char ppath[PATH_MAX] = "(null)";
  proc_pidpath(message.pid, ppath, PATH_MAX);

  NSString *user, *group;
  struct passwd *pw = getpwuid(message.uid);
  if (pw) user = @(pw->pw_name);
  struct group *gr = getgrgid(message.gid);
  if (gr) group = @(gr->gr_name);

  outStr = [outStr stringByAppendingFormat:(@"|pid=%d|ppid=%d|process=%s|processpath=%s|"
                                            @"uid=%d|user=%@|gid=%d|group=%@"),
                                           message.pid, message.ppid, message.pname, ppath,
                                           message.uid, user, message.gid, group];
  if (sha256) {
    outStr = [outStr stringByAppendingFormat:@"|sha256=%@", sha256];
  }

  LOGI(@"%@", outStr);
}

- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message {
  [self logExecution:message withDecision:cd];
}

- (void)logAllowedExecution:(santa_message_t)message {
  SNTCachedDecision *cd = self.detailStore[@(message.vnode_id)];
  [self logExecution:message withDecision:cd];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  NSString *d, *r, *args, *outLog;

  switch (cd.decision) {
    case SNTEventStateAllowBinary:
      d = @"ALLOW";
      r = @"BINARY";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateAllowCertificate:
      d = @"ALLOW";
      r = @"CERTIFICATE";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateAllowScope:
      d = @"ALLOW";
      r = @"SCOPE";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateAllowUnknown:
      d = @"ALLOW";
      r = @"UNKNOWN";
      args = [self argsForPid:message.pid];
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
      args = [self argsForPid:message.pid];
      break;
  }

  outLog = [NSString stringWithFormat:@"action=EXEC|decision=%@|reason=%@", d, r];

  if (cd.decisionExtra) {
    outLog = [outLog stringByAppendingFormat:@"|explain=%@", cd.decisionExtra];
  }

  outLog = [outLog stringByAppendingFormat:@"|sha256=%@|path=%@|args=%@", cd.sha256,
                                           [self sanitizeString:@(message.path)],
                                           [self sanitizeString:args]];

  if (cd.certSHA256) {
    outLog = [outLog stringByAppendingFormat:@"|cert_sha256=%@|cert_cn=%@", cd.certSHA256,
                                             [self sanitizeString:cd.certCommonName]];
  }

  if (cd.quarantineURL) {
    outLog = [outLog stringByAppendingFormat:@"|quarantine_url=%@",
                                             [self sanitizeString:cd.quarantineURL]];
  }

  NSString *user, *group;
  struct passwd *pw = getpwuid(message.uid);
  if (pw) user = @(pw->pw_name);
  struct group *gr = getgrgid(message.gid);
  if (gr) group = @(gr->gr_name);

  outLog = [outLog stringByAppendingFormat:@"|pid=%d|ppid=%d|uid=%d|user=%@|gid=%d|group=%@",
                                           message.pid, message.ppid, message.uid, user,
                                           message.gid, group];

  LOGI(@"%@", outLog);
}

#pragma mark Helpers

- (NSString *)sanitizeString:(NSString *)inStr {
  inStr = [inStr stringByReplacingOccurrencesOfString:@"|" withString:@"<pipe>"];
  inStr = [inStr stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
  inStr = [inStr stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"];
  return inStr;
}

- (NSString *)argsForPid:(pid_t)pid {
  int mib[3];

  // Get size of buffer required to store process arguments.
  mib[0] = CTL_KERN;
  mib[1] = KERN_ARGMAX;
  int argmax;
  size_t size = sizeof(argmax);

  if (sysctl(mib, 2, &argmax, &size, NULL, 0) == -1) return nil;

  // Create buffer to store args
  NSMutableData *argsdata = [NSMutableData dataWithCapacity:argmax];
  char *argsdatabytes = (char *)argsdata.mutableBytes;

  // Fetch args
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROCARGS2;
  mib[2] = pid;
  size = (size_t)argmax;
  if (sysctl(mib, 3, argsdatabytes, &size, NULL, 0) == -1) return nil;

  // Get argc
  int argc;
  memcpy(&argc, argsdatabytes, sizeof(argc));

  // Get pointer to beginning of string space
  char *cp = (char *)argsdatabytes + sizeof(argc);

  // Skip over exec_path
  for (; cp < &argsdatabytes[size]; ++cp) {
    if (*cp == '\0') {
      cp++;
      break;
    }
  }

  // Skip trailing NULL bytes
  for (; cp < &argsdatabytes[size]; ++cp) {
    if (*cp != '\0') break;
  }

  // Loop over the argv array, stripping newlines in each arg and putting in a new array.
  NSMutableArray *args = [NSMutableArray arrayWithCapacity:argc];
  for (int i = 0; i < argc; ++i) {
    NSString *arg = @(cp);
    if (arg) [args addObject:arg];

    // Move the pointer past this string and the terminator at the end.
    cp += strlen(cp) + 1;
  }

  // Return the args as a space-separated list
  return [args componentsJoinedByString:@" "];
}

@end
