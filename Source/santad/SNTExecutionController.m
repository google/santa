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

#import "SNTExecutionController.h"

#include <libproc.h>
#include <utmpx.h>

#include "SNTLogging.h"

#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDriverManager.h"
#import "SNTDropRootPrivs.h"
#import "SNTEventTable.h"
#import "SNTFileInfo.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCNotifierInterface.h"

@implementation SNTExecutionController

#pragma mark Initializers

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager
                            ruleTable:(SNTRuleTable *)ruleTable
                           eventTable:(SNTEventTable *)eventTable
                   notifierConnection:(SNTXPCConnection *)notifier {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierConnection = notifier;
    LOGI(@"Log format: Decision (A|D), Reason (B|C|S|?), SHA-256, Path, Cert SHA-256, Cert CN");

    // Workaround for xpcproxy/libsecurity bug on Yosemite
    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[SNTCodesignChecker alloc] initWithSelf];
  }
  return self;
}

#pragma mark Binary Validation

- (void)validateBinaryWithPath:(NSString *)path
                      userName:(NSString *)userName
                           pid:(NSNumber *)pid
                          ppid:(NSNumber *)ppid
                       vnodeId:(uint64_t)vnodeId {
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:path];
  NSString *sha256 = [binInfo SHA256];

  // These will be filled in either in later steps
  santa_action_t respondedAction = ACTION_UNSET;
  SNTRule *rule;

  // Get name of parent process. Do this before responding to be sure parent doesn't go away.
  char pname[PROC_PIDPATHINFO_MAXSIZE];
  proc_name([ppid intValue], pname, PROC_PIDPATHINFO_MAXSIZE);

  // Step 1 - binary rule?
  rule = [self.ruleTable binaryRuleForSHA256:sha256];
  if (rule) {
    respondedAction = [self actionForRuleState:rule.state];
    [self.driverManager postToKernelAction:respondedAction forVnodeID:vnodeId];
  }

  SNTCodesignChecker *csInfo = [[SNTCodesignChecker alloc] initWithBinaryPath:path];

  // Step 2 - cert rule?
  if (!rule) {
    rule = [self.ruleTable certificateRuleForSHA256:csInfo.leafCertificate.SHA256];
    if (rule) {
      respondedAction = [self actionForRuleState:rule.state];
      [self.driverManager postToKernelAction:respondedAction forVnodeID:vnodeId];
    }
  }

  // Step 3 - in scope?
  if (![self fileIsInScope:path]) {
    [self.driverManager postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW forVnodeID:vnodeId];
    [self logDecisionForEventState:EVENTSTATE_ALLOW_SCOPE sha256:sha256 path:path leafCert:nil];
    return;
  }

  // Step 4 - default rule :-(
  if (!rule) {
    respondedAction = [self defaultDecision];
    [self.driverManager postToKernelAction:respondedAction forVnodeID:vnodeId];
  }

  // Step 5 - log to database and potentially alert user
  if (respondedAction == ACTION_RESPOND_CHECKBW_DENY ||
      !rule ||
      [[SNTConfigurator configurator] logAllEvents]) {
    SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
    se.fileSHA256 = sha256;
    se.filePath = path;
    se.fileBundleID = [binInfo bundleIdentifier];
    se.fileBundleName = [binInfo bundleName];

    if ([binInfo bundleShortVersionString]) {
      se.fileBundleVersionString = [binInfo bundleShortVersionString];
    }

    if ([binInfo bundleVersion]) {
      se.fileBundleVersion = [binInfo bundleVersion];
    }

    se.signingChain = csInfo.certificates;
    se.executingUser = userName;
    se.occurrenceDate = [[NSDate alloc] init];
    se.decision = [self eventStateForDecision:respondedAction type:rule.type];
    se.pid = pid;
    se.ppid = ppid;
    se.parentName = @(pname);

    NSArray *loggedInUsers, *currentSessions;
    [self loggedInUsers:&loggedInUsers sessions:&currentSessions];
    se.currentSessions = currentSessions;
    se.loggedInUsers = loggedInUsers;

    [self.eventTable addStoredEvent:se];

    if (respondedAction == ACTION_RESPOND_CHECKBW_DENY) {
      // So the server has something to show the user straight away, initiate an event
      // upload for the blocked binary rather than waiting for the next sync.
      // The event upload is skipped if the full path is equal to that of santactl so that
      /// on the off chance that santactl is not whitelisted, we don't get into an infinite loop.
      if (![path isEqual:@(kSantaCtlPath)]) {
        [self initiateEventUploadForSHA256:sha256];
      }

      if (!rule || rule.state != RULESTATE_SILENT_BLACKLIST) {
        [[self.notifierConnection remoteObjectProxy] postBlockNotification:se
                                                         withCustomMessage:rule.customMsg];
      }
    }
  }

  // Step 6 - log to log file
  [self logDecisionForEventState:[self eventStateForDecision:respondedAction type:rule.type]
                          sha256:sha256
                            path:path
                        leafCert:csInfo.leafCertificate];
}

///
///  Checks whether the file at @c path is in-scope for checking with Santa.
///
///  Files that are out of scope:
///    + Non Mach-O files that are not part of an installer package.
///    + Files in whitelisted directories.
///
///  @return @c YES if file is in scope, @c NO otherwise.
///
- (BOOL)fileIsInScope:(NSString *)path {
  // Determine if file is within a whitelisted directory.
  if ([self pathIsInWhitelistedDir:path]) {
    return NO;
  }

  // If file is not a Mach-O file, we're not interested unless it's part of an install package.
  // TODO(rah): Consider adding an option to check all scripts.
  // TODO(rah): Consider adding an option to disable package script checks.
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:path];
  if (![binInfo isMachO] && ![path hasPrefix:@"/private/tmp/PKInstallSandbox."]) {
    return NO;
  }

  return YES;
}

- (BOOL)pathIsInWhitelistedDir:(NSString *)path {
  // TODO(rah): Implement this.
  return NO;
}

- (santa_eventstate_t)eventStateForDecision:(santa_action_t)decision type:(santa_ruletype_t)type {
  if (decision == ACTION_RESPOND_CHECKBW_ALLOW) {
    if (type == RULETYPE_BINARY) {
      return EVENTSTATE_ALLOW_BINARY;
    } else if (type == RULETYPE_CERT) {
      return EVENTSTATE_ALLOW_CERTIFICATE;
    } else {
      return EVENTSTATE_ALLOW_UNKNOWN;
    }
  } else if (decision == ACTION_RESPOND_CHECKBW_DENY) {
    if (type == RULETYPE_BINARY) {
      return EVENTSTATE_BLOCK_BINARY;
    } else if (decision == RULETYPE_CERT) {
      return EVENTSTATE_BLOCK_CERTIFICATE;
    } else {
      return EVENTSTATE_BLOCK_UNKNOWN;
    }
  } else {
    return EVENTSTATE_UNKNOWN;
  }
}

- (void)logDecisionForEventState:(santa_eventstate_t)eventState
                          sha256:(NSString *)sha256
                            path:(NSString *)path
                        leafCert:(SNTCertificate *)cert {
  NSString *d, *r, *outLog;

  switch (eventState) {
    case EVENTSTATE_ALLOW_BINARY:
      d = @"A"; r = @"B"; break;
    case EVENTSTATE_ALLOW_CERTIFICATE:
      d = @"A"; r = @"C"; break;
    case EVENTSTATE_ALLOW_SCOPE:
      d = @"A"; r = @"S"; break;
    case EVENTSTATE_ALLOW_UNKNOWN:
      d = @"A"; r = @"?"; break;
    case EVENTSTATE_BLOCK_BINARY:
      d = @"D"; r = @"B"; break;
    case EVENTSTATE_BLOCK_CERTIFICATE:
      d = @"D"; r = @"C"; break;
    case EVENTSTATE_BLOCK_UNKNOWN:
      d = @"D"; r = @"?"; break;
    default:
      d = @"?"; r = @"?"; break;
  }

  // Ensure there are no pipes in the path name (as this will be confusing in the log)
  NSString *printPath = [path stringByReplacingOccurrencesOfString:@"|" withString:@"<pipe>"];

  if (cert && cert.SHA256 && cert.commonName) {
    // Also ensure there are no pipes in the cert's common name.
    NSString *printCommonName =
        [cert.commonName stringByReplacingOccurrencesOfString:@"|" withString:@"<pipe>"];
    outLog = [NSString stringWithFormat:@"%@|%@|%@|%@|%@|%@",
                 d, r, sha256, printPath, cert.SHA256, printCommonName];
  } else {
    outLog = [NSString stringWithFormat:@"%@|%@|%@|%@", d, r, sha256, printPath];
  }

  // Now make sure none of the log line has a newline in it.
  LOGI(@"%@", [[outLog componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]
                                   componentsJoinedByString:@" "]);
}

- (void)initiateEventUploadForSHA256:(NSString *)sha256 {
  signal(SIGCHLD, SIG_IGN);
  pid_t child = fork();
  if (child == 0) {
    fclose(stdout);
    fclose(stderr);

    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      _exit(1);
    }

    _exit(execl(kSantaCtlPath, kSantaCtlPath, "sync", "singleevent", [sha256 UTF8String], NULL));
  }
}

- (santa_action_t)defaultDecision {
  switch ([[SNTConfigurator configurator] clientMode]) {
    case CLIENTMODE_MONITOR: return ACTION_RESPOND_CHECKBW_ALLOW;
    case CLIENTMODE_LOCKDOWN: return ACTION_RESPOND_CHECKBW_DENY;
    default: return ACTION_RESPOND_CHECKBW_DENY;  // This can't happen.
  }
}

- (santa_action_t)actionForRuleState:(santa_rulestate_t)state {
  switch (state) {
    case RULESTATE_WHITELIST:
      return ACTION_RESPOND_CHECKBW_ALLOW;
    case RULESTATE_BLACKLIST:
    case RULESTATE_SILENT_BLACKLIST:
      return ACTION_RESPOND_CHECKBW_DENY;
    default:
      return ACTION_ERROR;
  }
}

- (void)loggedInUsers:(NSArray **)users sessions:(NSArray **)sessions {
  struct utmpx *nxt;

  NSMutableDictionary *loggedInUsers = [[NSMutableDictionary alloc] init];
  NSMutableDictionary *loggedInHosts = [[NSMutableDictionary alloc] init];

  while ((nxt = getutxent())) {
    if (nxt->ut_type != USER_PROCESS) continue;

    NSString *userName = [NSString stringWithUTF8String:nxt->ut_user];

    NSString *sessionName;
    if (strnlen(nxt->ut_host, 1) > 0) {
      sessionName = [NSString stringWithFormat:@"%s@%s", nxt->ut_user, nxt->ut_host];
    } else {
      sessionName = [NSString stringWithFormat:@"%s@%s", nxt->ut_user, nxt->ut_line];
    }

    if ([userName length] > 0) {
      loggedInUsers[userName] = [NSNull null];
    }

    if ([sessionName length] > 1) {
      loggedInHosts[sessionName] = [NSNull null];
    }
  }

  endutxent();

  *users = [loggedInUsers allKeys];
  *sessions = [loggedInHosts allKeys];
}

@end
