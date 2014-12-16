/// Copyright 2014 Google Inc. All rights reserved.
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

#include <utmpx.h>

#include "SNTLogging.h"

#import "SNTBinaryInfo.h"
#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTDriverManager.h"
#import "SNTDropRootPrivs.h"
#import "SNTEventTable.h"
#import "SNTNotificationMessage.h"
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
                        operatingMode:(santa_clientmode_t)operatingMode
                   notifierConnection:(SNTXPCConnection *)notifier {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _operatingMode = operatingMode;
    _notifierConnection = notifier;
    LOGI(@"Log format: Decision (A|D), Reason (B|C), SHA-1, Path, Cert SHA-1, Cert CN");

    // Workaround for xpcproxy/libsecurity bug on Yosemite
    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[SNTCodesignChecker alloc] initWithSelf];
  }
  return self;
}

#pragma mark Binary Validation

- (void)validateBinaryWithSHA1:(NSString *)sha1
                          path:(NSString *)path
                      userName:(NSString *)userName
                           pid:(NSNumber *)pid
                       vnodeId:(uint64_t)vnodeId {
  // Step 1 - in scope?
  if (![self fileIsInScope:path]) {
    [self.driverManager postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW forVnodeID:vnodeId];
    LOGD(@"File out of scope: %@", path);
    return;
  }

  // These will be filled in either in step 2, 3 or 4.
  santa_action_t respondedAction = ACTION_UNSET;
  SNTRule *rule;

  // Step 2 - binary rule?
  rule = [self.ruleTable binaryRuleForSHA1:sha1];
  if (rule) {
    respondedAction = [self actionForRuleState:rule.state];
    [self.driverManager postToKernelAction:respondedAction forVnodeID:vnodeId];
  }

  SNTBinaryInfo *binInfo = [[SNTBinaryInfo alloc] initWithPath:path];
  SNTCodesignChecker *csInfo = [[SNTCodesignChecker alloc] initWithBinaryPath:path];

  // Step 3 - cert rule?
  if (!rule) {
    rule = [self.ruleTable certificateRuleForSHA1:csInfo.leafCertificate.SHA1];
    if (rule) {
      respondedAction = [self actionForRuleState:rule.state];
      [self.driverManager postToKernelAction:respondedAction forVnodeID:vnodeId];
    }
  }

  // Step 4 - default rule :-(
  if (!rule) {
    respondedAction = [self defaultDecision];
    [self.driverManager postToKernelAction:respondedAction forVnodeID:vnodeId];
  }

  // Step 5 - log to database
  if (respondedAction == ACTION_RESPOND_CHECKBW_DENY || !rule) {
    SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
    se.fileSHA1 = sha1;
    se.filePath = path;
    se.fileBundleID = [binInfo bundleIdentifier];
    se.fileBundleName = [binInfo bundleName];

    if ([binInfo bundleShortVersionString]) {
      se.fileBundleVersionString = [binInfo bundleShortVersionString];
    }

    if ([binInfo bundleVersion]) {
      se.fileBundleVersion = [binInfo bundleVersion];
    }

    se.certSHA1 = csInfo.leafCertificate.SHA1;
    se.certCN = csInfo.leafCertificate.commonName;
    se.certOrg = csInfo.leafCertificate.orgName;
    se.certOU = csInfo.leafCertificate.orgUnit;
    se.certValidFromDate = csInfo.leafCertificate.validFrom;
    se.certValidUntilDate = csInfo.leafCertificate.validUntil;
    se.executingUser = userName;
    se.occurrenceDate = [[NSDate alloc] init];
    se.decision = [self eventStateForDecision:respondedAction type:rule.type];
    se.pid = pid;

    NSArray *loggedInUsers, *currentSessions;
    [self loggedInUsers:&loggedInUsers sessions:&currentSessions];
    se.currentSessions = currentSessions;
    se.loggedInUsers = loggedInUsers;

    [self.eventTable addStoredEvent:se];
  }

  // Step 6 - log to log file
  [self logDecisionForEventState:[self eventStateForDecision:respondedAction type:rule.type]
                            sha1:sha1
                            path:path
                        leafCert:csInfo.leafCertificate];

  // Step 7 - alert user
  if (respondedAction == ACTION_RESPOND_CHECKBW_DENY) {
    // So the server has something to show the user straight away, initiate an event
    // upload for the blocked binary rather than waiting for the next sync.
    // The event upload is skipped if the full path is equal to that of /usr/sbin/santactl so that
    /// on the off chance that santactl is not whitelisted, we don't get into an infinite loop.
    if (![path isEqual:@"/usr/sbin/santactl"]) {
      [self initiateEventUploadForSHA1:sha1];
    }

    SNTNotificationMessage *notMsg = [[SNTNotificationMessage alloc] init];
    notMsg.path = path;
    notMsg.SHA1 = sha1;
    notMsg.customMessage = rule.customMsg;
    notMsg.certificates = csInfo.certificates;
    [[self.notifierConnection remoteObjectProxy] postBlockNotification:notMsg];
  }
}

/**
 Checks whether the file at @c path is in-scope for checking with Santa.

 Files that are out of scope:
   + Non Mach-O files
   + Files in whitelisted directories.

 @return @c YES if file is in scope, @c NO otherwise.
**/
- (BOOL)fileIsInScope:(NSString *)path {
  // Determine if file is within a whitelisted directory.
  if ([self pathIsInWhitelistedDir:path]) {
    return NO;
  }

  // If file is not a Mach-O file, we're not interested.
  // TODO(rah): Consider adding an option to check scripts
  SNTBinaryInfo *binInfo = [[SNTBinaryInfo alloc] initWithPath:path];
  if (![binInfo isMachO]) {
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
                            sha1:(NSString *)sha1
                            path:(NSString *)path
                        leafCert:(SNTCertificate *)cert {
  NSString *d, *r, *outLog;

  switch (eventState) {
    case EVENTSTATE_ALLOW_BINARY:
      d = @"A"; r = @"B"; break;
    case EVENTSTATE_ALLOW_CERTIFICATE:
      d = @"A"; r = @"C"; break;
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

  // Ensure there are no commas in the path name (as this will be confusing in the log)
  NSString *printPath = [path stringByReplacingOccurrencesOfString:@"," withString:@"<comma>"];

  if (cert && cert.SHA1 && cert.commonName) {
    // Also ensure there are no commas in the cert's common name.
    NSString *printCommonName = [cert.commonName stringByReplacingOccurrencesOfString:@","
                                                                           withString:@"<comma>"];
    outLog = [NSString stringWithFormat:@"%@,%@,%@,%@,%@,%@", d, r, sha1, printPath,
                 cert.SHA1, printCommonName];
  } else {
    outLog = [NSString stringWithFormat:@"%@,%@,%@,%@", d, r, sha1, printPath];
  }

  // Now make sure none of the log line has a newline in it.
  LOGI(@"%@", [[outLog componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]
                                   componentsJoinedByString:@" "]);
}

- (void)initiateEventUploadForSHA1:(NSString *)sha1 {
  signal(SIGCHLD, SIG_IGN);
  pid_t child = fork();
  if (child == 0) {
    fclose(stdout);
    fclose(stderr);

    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      exit(1);
    }

    exit(execl("/usr/sbin/santactl", "/usr/sbin/santactl", "sync",
               "singleevent", [sha1 UTF8String], NULL));
  }
}

- (santa_action_t)defaultDecision {
  switch (self.operatingMode) {
    case CLIENTMODE_MONITOR:
      return ACTION_RESPOND_CHECKBW_ALLOW;
    case CLIENTMODE_LOCKDOWN:
      return ACTION_RESPOND_CHECKBW_DENY;
    default:
      // This should never happen, panic and lockdown.
      LOGE(@"Client mode is unset while enforcement is in effect. Blocking.");
      return ACTION_RESPOND_CHECKBW_DENY;
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

    if (userName && ![userName isEqual:@""]) {
      loggedInUsers[userName] = @"";
    }

    if (sessionName && ![sessionName isEqual:@":"]) {
      loggedInHosts[sessionName] = @"";
    }
  }

  endutxent();

  *users = [loggedInUsers allKeys];
  *sessions = [loggedInHosts allKeys];
}

@end
