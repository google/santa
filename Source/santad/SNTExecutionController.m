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
#include <pwd.h>
#include <utmpx.h>

#include "SNTLogging.h"

#import "SNTCachedDecision.h"
#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDriverManager.h"
#import "SNTDropRootPrivs.h"
#import "SNTEventLog.h"
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
                   notifierConnection:(SNTXPCConnection *)notifier
                             eventLog:(SNTEventLog *)eventLog {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierConnection = notifier;
    _eventLog = eventLog;

    // Workaround for xpcproxy/libsecurity bug on Yosemite
    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[SNTCodesignChecker alloc] initWithSelf];
  }
  return self;
}

#pragma mark Binary Validation

- (santa_eventstate_t)makeDecision:(SNTCachedDecision *)cd binaryInfo:(SNTFileInfo *)fi {
  SNTRule *rule = [self.ruleTable binaryRuleForSHA256:cd.sha256];
  if (rule) {
    switch (rule.state) {
      case RULESTATE_WHITELIST:
        return EVENTSTATE_ALLOW_BINARY;
      case RULESTATE_SILENT_BLACKLIST:
        cd.silentBlock = YES;
      case RULESTATE_BLACKLIST:
        cd.customMsg = rule.customMsg;
        return EVENTSTATE_BLOCK_BINARY;
      default: break;
    }
  }

  rule = [self.ruleTable certificateRuleForSHA256:cd.certSHA256];
  if (rule) {
    switch (rule.state) {
      case RULESTATE_WHITELIST:
        return EVENTSTATE_ALLOW_CERTIFICATE;
      case RULESTATE_SILENT_BLACKLIST:
        cd.silentBlock = YES;
      case RULESTATE_BLACKLIST:
        cd.customMsg = rule.customMsg;
        return EVENTSTATE_BLOCK_CERTIFICATE;
      default: break;
    }
  }

  if (![self fileIsInScope:fi]) {
    return EVENTSTATE_ALLOW_SCOPE;
  }

  if (fi.isMissingPageZero) {
    LOGW(@"File has bad/missing __PAGEZERO segment. Denying execution");
    return EVENTSTATE_BLOCK_SCOPE;
  }

  switch ([[SNTConfigurator configurator] clientMode]) {
    case CLIENTMODE_MONITOR: return EVENTSTATE_ALLOW_UNKNOWN;
    case CLIENTMODE_LOCKDOWN: return EVENTSTATE_BLOCK_UNKNOWN;
    default: return EVENTSTATE_BLOCK_UNKNOWN;
  }
}

- (void)validateBinaryWithMessage:(santa_message_t)message {
  // Get info about the file. If we can't get this info, allow execution and log an error.
  NSError *fileInfoError;
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:@(message.path) error:&fileInfoError];
  if (!binInfo) {
    LOGW(@"Failed to read file %@: %@", binInfo.path, fileInfoError.localizedDescription);
    [self.driverManager postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                forVnodeID:message.vnode_id];
    return;
  }

  // Get codesigning info about the file.
  SNTCodesignChecker *csInfo = [[SNTCodesignChecker alloc] initWithBinaryPath:binInfo.path];

  // Actually make the decision.
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = binInfo.SHA256;
  cd.certCommonName = csInfo.leafCertificate.commonName;
  cd.certSHA256 = csInfo.leafCertificate.SHA256;
  cd.vnodeId = message.vnode_id;
  cd.decision = [self makeDecision:cd binaryInfo:binInfo];

  // Save decision details for logging the execution later.
  santa_action_t action = [self actionForEventState:cd.decision];
  if (action == ACTION_RESPOND_CHECKBW_ALLOW) [self.eventLog saveDecisionDetails:cd];

  // Get name of parent process. Do this before responding to be sure parent doesn't go away.
  char pname[PROC_PIDPATHINFO_MAXSIZE];
  proc_name(message.ppid, pname, PROC_PIDPATHINFO_MAXSIZE);

  // Send the decision to the kernel.
  [self.driverManager postToKernelAction:action forVnodeID:cd.vnodeId];

  // Log to database if necessary.
  if ((cd.decision != EVENTSTATE_ALLOW_BINARY &&
       cd.decision != EVENTSTATE_ALLOW_CERTIFICATE &&
       cd.decision != EVENTSTATE_ALLOW_SCOPE) || [[SNTConfigurator configurator] logAllEvents]) {

    SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
    se.parentName = @(pname);
    se.fileSHA256 = cd.sha256;
    se.signingChain = csInfo.certificates;
    se.occurrenceDate = [[NSDate alloc] init];
    se.filePath = binInfo.path;
    se.pid = @(message.pid);
    se.ppid = @(message.ppid);

    se.fileBundleID = [binInfo bundleIdentifier];
    se.fileBundleName = [binInfo bundleName];

    if ([binInfo bundleShortVersionString]) {
      se.fileBundleVersionString = [binInfo bundleShortVersionString];
    }

    if ([binInfo bundleVersion]) {
      se.fileBundleVersion = [binInfo bundleVersion];
    }

    struct passwd *user = getpwuid(message.uid);
    endpwent();
    if (user) {
      se.executingUser = @(user->pw_name);
    }

    NSArray *loggedInUsers, *currentSessions;
    [self loggedInUsers:&loggedInUsers sessions:&currentSessions];
    se.currentSessions = currentSessions;
    se.loggedInUsers = loggedInUsers;

    [self.eventTable addStoredEvent:se];

    // If binary was blocked, do the needful
    if (action != ACTION_RESPOND_CHECKBW_ALLOW) {
      [self.eventLog logDeniedExecution:cd withMessage:message];

      // So the server has something to show the user straight away, initiate an event
      // upload for the blocked binary rather than waiting for the next sync.
      [self initiateEventUploadForEvent:se];

      if (!cd.silentBlock) {
        [[self.notifierConnection remoteObjectProxy] postBlockNotification:se
                                                         withCustomMessage:cd.customMsg];
      }
    }
  }
}

///
///  Checks whether the file at @c path is in-scope for checking with Santa.
///
///  Files that are out of scope:
///    + Non Mach-O files that are not part of an installer package.
///    + Files in whitelisted path.
///
///  @return @c YES if file is in scope, @c NO otherwise.
///
- (BOOL)fileIsInScope:(SNTFileInfo *)fi {
  // Determine if file is within a whitelisted path
  NSRegularExpression *re = [[SNTConfigurator configurator] whitelistPathRegex];
  if ([re numberOfMatchesInString:fi.path
                          options:0
                            range:NSMakeRange(0, fi.path.length)]) {
    return NO;
  }

  // If file is not a Mach-O file, we're not interested unless it's part of an install package.
  // TODO(rah): Consider adding an option to check all scripts.
  // TODO(rah): Consider adding an option to disable package script checks.
  if (!fi.isMachO && ![fi.path hasPrefix:@"/private/tmp/PKInstallSandbox."]) {
    return NO;
  }

  return YES;
}

- (void)initiateEventUploadForEvent:(SNTStoredEvent *)event {
  // The event upload is skipped if the full path is equal to that of santactl so that
  // on the off chance that santactl is not whitelisted, we don't get into an infinite loop.
  // It's also skipped if there isn't a server configured or the last sync caused a backoff.
  if ([event.filePath isEqual:@(kSantaCtlPath)] ||
      ![[SNTConfigurator configurator] syncBaseURL] ||
      [[SNTConfigurator configurator] syncBackOff]) return;

  if (fork() == 0) {
    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      _exit(EPERM);
    }

    _exit(execl(kSantaCtlPath, kSantaCtlPath, "sync", "singleevent",
                [event.fileSHA256 UTF8String], NULL));
  }
}

- (santa_action_t)actionForEventState:(santa_eventstate_t)state {
  switch (state) {
    case EVENTSTATE_ALLOW_BINARY:
    case EVENTSTATE_ALLOW_CERTIFICATE:
    case EVENTSTATE_ALLOW_SCOPE:
    case EVENTSTATE_ALLOW_UNKNOWN:
      return ACTION_RESPOND_CHECKBW_ALLOW;
    case EVENTSTATE_BLOCK_BINARY:
    case EVENTSTATE_BLOCK_CERTIFICATE:
    case EVENTSTATE_BLOCK_SCOPE:
    case EVENTSTATE_BLOCK_UNKNOWN:
      return ACTION_RESPOND_CHECKBW_DENY;
    default:
      LOGW(@"Invalid event state %d", state);
      return ACTION_RESPOND_CHECKBW_DENY;
  }
}

- (void)loggedInUsers:(NSArray **)users sessions:(NSArray **)sessions {
  NSMutableDictionary *loggedInUsers = [[NSMutableDictionary alloc] init];
  NSMutableDictionary *loggedInHosts = [[NSMutableDictionary alloc] init];

  struct utmpx *nxt;
  while ((nxt = getutxent())) {
    if (nxt->ut_type != USER_PROCESS) continue;

    NSString *userName = [NSString stringWithUTF8String:nxt->ut_user];

    NSString *sessionName;
    if (strnlen(nxt->ut_host, 1) > 0) {
      sessionName = [NSString stringWithFormat:@"%s@%s", nxt->ut_user, nxt->ut_host];
    } else {
      sessionName = [NSString stringWithFormat:@"%s@%s", nxt->ut_user, nxt->ut_line];
    }

    if (userName.length > 0) {
      loggedInUsers[userName] = [NSNull null];
    }

    if (sessionName.length > 1) {
      loggedInHosts[sessionName] = [NSNull null];
    }
  }

  endutxent();

  *users = [loggedInUsers allKeys];
  *sessions = [loggedInHosts allKeys];
}

@end
