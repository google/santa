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

#import "MOLCertificate.h"
#import "MOLCodesignChecker.h"
#import "SNTBlockMessage.h"
#import "SNTCachedDecision.h"
#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDriverManager.h"
#import "SNTDropRootPrivs.h"
#import "SNTEventLog.h"
#import "SNTEventTable.h"
#import "SNTFileInfo.h"
#import "SNTNotificationQueue.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"
#import "SNTStoredEvent.h"

@interface SNTExecutionController ()
@property SNTDriverManager *driverManager;
@property SNTEventLog *eventLog;
@property SNTEventTable *eventTable;
@property SNTNotificationQueue *notifierQueue;
@property SNTRuleTable *ruleTable;

@property NSMutableDictionary *uploadBackoff;
@property dispatch_queue_t eventQueue;
@end

@implementation SNTExecutionController

#pragma mark Initializers

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager
                            ruleTable:(SNTRuleTable *)ruleTable
                           eventTable:(SNTEventTable *)eventTable
                        notifierQueue:(SNTNotificationQueue *)notifierQueue
                             eventLog:(SNTEventLog *)eventLog {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierQueue = notifierQueue;
    _eventLog = eventLog;

    _uploadBackoff = [NSMutableDictionary dictionaryWithCapacity:128];
    _eventQueue = dispatch_queue_create("com.google.santad.event_upload", DISPATCH_QUEUE_SERIAL);

    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[MOLCodesignChecker alloc] initWithSelf];
  }
  return self;
}

#pragma mark Binary Validation

- (SNTEventState)makeDecision:(SNTCachedDecision *)cd binaryInfo:(SNTFileInfo *)fi {
  SNTRule *rule = [_ruleTable binaryRuleForSHA256:cd.sha256];
  if (rule) {
    switch (rule.state) {
      case SNTRuleStateWhitelist:
        return SNTEventStateAllowBinary;
      case SNTRuleStateSilentBlacklist:
        cd.silentBlock = YES;
      case SNTRuleStateBlacklist:
        cd.customMsg = rule.customMsg;
        return SNTEventStateBlockBinary;
      default: break;
    }
  }

  rule = [_ruleTable certificateRuleForSHA256:cd.certSHA256];
  if (rule) {
    switch (rule.state) {
      case SNTRuleStateWhitelist:
        return SNTEventStateAllowCertificate;
      case SNTRuleStateSilentBlacklist:
        cd.silentBlock = YES;
      case SNTRuleStateBlacklist:
        cd.customMsg = rule.customMsg;
        return SNTEventStateBlockCertificate;
      default: break;
    }
  }

  NSString *msg = [self fileIsScopeBlacklisted:fi];
  if (msg) {
    cd.decisionExtra = msg;
    return SNTEventStateBlockScope;
  }

  msg = [self fileIsScopeWhitelisted:fi];
  if (msg) {
    cd.decisionExtra = msg;
    return SNTEventStateAllowScope;
  }

  switch ([[SNTConfigurator configurator] clientMode]) {
    case SNTClientModeMonitor: return SNTEventStateAllowUnknown;
    case SNTClientModeLockdown: return SNTEventStateBlockUnknown;
    default: return SNTEventStateBlockUnknown;
  }
}

- (void)validateBinaryWithMessage:(santa_message_t)message {
  // Get info about the file. If we can't get this info, allow execution and log an error.
  NSError *fileInfoError;
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:@(message.path) error:&fileInfoError];
  if (!binInfo) {
    LOGW(@"Failed to read file %@: %@", binInfo.path, fileInfoError.localizedDescription);
    [_driverManager postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:message.vnode_id];
    return;
  }

  // PrinterProxy workaround, see description above the method for more details.
  if ([self printerProxyWorkaround:binInfo]) return;

  // Get codesigning info about the file.
  MOLCodesignChecker *csInfo = [[MOLCodesignChecker alloc] initWithBinaryPath:binInfo.path];

  // Actually make the decision.
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = binInfo.SHA256;
  cd.certCommonName = csInfo.leafCertificate.commonName;
  cd.certSHA256 = csInfo.leafCertificate.SHA256;
  cd.vnodeId = message.vnode_id;
  cd.quarantineURL = binInfo.quarantineDataURL;
  cd.decision = [self makeDecision:cd binaryInfo:binInfo];

  // Save decision details for logging the execution later.
  santa_action_t action = [self actionForEventState:cd.decision];
  if (action == ACTION_RESPOND_ALLOW) [_eventLog saveDecisionDetails:cd];

  // Send the decision to the kernel.
  [_driverManager postToKernelAction:action forVnodeID:cd.vnodeId];

  // Log to database if necessary.
  if (cd.decision != SNTEventStateAllowBinary &&
      cd.decision != SNTEventStateAllowCertificate &&
      cd.decision != SNTEventStateAllowScope) {
    SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
    se.occurrenceDate = [[NSDate alloc] init];
    se.fileSHA256 = cd.sha256;
    se.filePath = binInfo.path;
    se.decision = cd.decision;

    se.signingChain = csInfo.certificates;
    se.pid = @(message.pid);
    se.ppid = @(message.ppid);
    se.parentName = @(message.pname);

    // Bundle data
    se.fileBundleID = [binInfo bundleIdentifier];
    se.fileBundleName = [binInfo bundleName];
    se.fileBundlePath = [binInfo bundlePath];
    if ([binInfo bundleShortVersionString]) {
      se.fileBundleVersionString = [binInfo bundleShortVersionString];
    }
    if ([binInfo bundleVersion]) {
      se.fileBundleVersion = [binInfo bundleVersion];
    }

    // User data
    struct passwd *user = getpwuid(message.uid);
    if (user) se.executingUser = @(user->pw_name);
    NSArray *loggedInUsers, *currentSessions;
    [self loggedInUsers:&loggedInUsers sessions:&currentSessions];
    se.currentSessions = currentSessions;
    se.loggedInUsers = loggedInUsers;

    // Quarantine data
    se.quarantineDataURL = binInfo.quarantineDataURL;
    se.quarantineRefererURL = binInfo.quarantineRefererURL;
    se.quarantineTimestamp = binInfo.quarantineTimestamp;
    se.quarantineAgentBundleID = binInfo.quarantineAgentBundleID;

    dispatch_async(_eventQueue, ^{
      [_eventTable addStoredEvent:se];
    });

    // If binary was blocked, do the needful
    if (action != ACTION_RESPOND_ALLOW) {
      [_eventLog logDeniedExecution:cd withMessage:message];

      // So the server has something to show the user straight away, initiate an event
      // upload for the blocked binary rather than waiting for the next sync.
      dispatch_async(_eventQueue, ^{
        [self initiateEventUploadForEvent:se];
      });

      if (!cd.silentBlock) {
        // Let the user know what happened, both on the terminal and in the GUI.
        NSAttributedString *s = [SNTBlockMessage attributedBlockMessageForEvent:se
                                                                  customMessage:cd.customMsg];
        NSMutableString *msg = [NSMutableString stringWithCapacity:1024];
        [msg appendFormat:@"\n\033[1mSanta\033[0m\n\n%@\n\n", s.string];
        [msg appendFormat:@"\033[1mPath:      \033[0m %@\n"
                          @"\033[1mIdentifier:\033[0m %@\n"
                          @"\033[1mParent:    \033[0m %@ (%@)\n\n",
            se.filePath, se.fileSHA256, se.parentName, se.ppid];
        NSURL *detailURL = [SNTBlockMessage eventDetailURLForEvent:se];
        if (detailURL) {
          [msg appendFormat:@"%@\n\n", detailURL.absoluteString];
        }
        [self printMessage:msg toTTYForPID:message.ppid];

        [_notifierQueue addEvent:se customMessage:cd.customMsg];
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
- (NSString *)fileIsScopeWhitelisted:(SNTFileInfo *)fi {
  // Determine if file is within a whitelisted path
  NSRegularExpression *re = [[SNTConfigurator configurator] whitelistPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Whitelist Regex";
  }

  // If file is not a Mach-O file, we're not interested unless it's part of an install package.
  // TODO(rah): Consider adding an option to check all scripts.
  // TODO(rah): Consider adding an option to disable package script checks.
  if (!fi.isMachO && ![fi.path hasPrefix:@"/private/tmp/PKInstallSandbox."]) {
    return @"Not a Mach-O";
  }

  return nil;
}

- (NSString *)fileIsScopeBlacklisted:(SNTFileInfo *)fi {
  NSRegularExpression *re = [[SNTConfigurator configurator] blacklistPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Blacklist Regex";
  }

  if ([[SNTConfigurator configurator] enablePageZeroProtection] && fi.isMissingPageZero) {
    return @"Missing __PAGEZERO";
  }

  return nil;
}

/**
  Workaround for issue with PrinterProxy.app.

  Every time a new printer is added to the machine, a copy of the PrinterProxy.app is copied from
  the Print.framework to ~/Library/Printers with the name of the printer as the name of the app.
  The binary inside is changed slightly (in a way that is unique to the printer name) and then
  re-signed with an adhoc signature. I don't know why this is done but it seems that the binary
  itself doesn't need to be changed as copying the old one back in-place seems to work,
  so that's what we do.

  If this workaround is applied the decision request is not responded to as the existing request
  is invalidated when the file is closed which will trigger a brand new request coming from the
  kernel.

  @param fi, SNTFileInfo object for the binary being executed.
  @return YES if the workaround was applied, NO otherwise.
*/
- (BOOL)printerProxyWorkaround:(SNTFileInfo *)fi {
  if ([fi.path hasSuffix:@"/Contents/MacOS/PrinterProxy"] &&
      [fi.path containsString:@"Library/Printers"]) {
    NSString *proxyPath = (@"/System/Library/Frameworks/Carbon.framework/Versions/Current/"
                           @"Frameworks/Print.framework/Versions/Current/Plugins/PrinterProxy.app/"
                           @"Contents/MacOS/PrinterProxy");
    SNTFileInfo *proxyFi = [[SNTFileInfo alloc] initWithPath:proxyPath];
    if ([proxyFi.SHA256 isEqual:fi.SHA256]) return NO;

    NSFileHandle *inFh = [NSFileHandle fileHandleForReadingAtPath:proxyPath];
    NSFileHandle *outFh = [NSFileHandle fileHandleForWritingAtPath:fi.path];
    [outFh writeData:[inFh readDataToEndOfFile]];
    [inFh closeFile];
    [outFh truncateFileAtOffset:[outFh offsetInFile]];
    [outFh synchronizeFile];
    [outFh closeFile];

    LOGW(@"PrinterProxy workaround applied to %@", fi.path);

    return YES;
  }
  return NO;
}

/**
  This runs `santactl sync` for the event that was just saved, so that the user
  has something to vote in straight away.

  This method is always called on a serial queue to ensure the backoff works properly
  and to keep this low-priority method away from the high-priority decision making threads.
*/
- (void)initiateEventUploadForEvent:(SNTStoredEvent *)event {
  // The event upload is skipped if the full path is equal to that of santactl so that
  // on the off chance that santactl is not whitelisted, we don't get into an infinite loop.
  // It's also skipped if there isn't a server configured or the last sync caused a backoff.
  if ([event.filePath isEqual:@(kSantaCtlPath)] ||
      ![[SNTConfigurator configurator] syncBaseURL] ||
      [[SNTConfigurator configurator] syncBackOff]) return;

  // The event upload is skipped if an event upload has been initiated for it in the
  // last 10 minutes.
  NSDate *backoff = self.uploadBackoff[event.fileSHA256];

  NSDate *now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) < 600) return;

  self.uploadBackoff[event.fileSHA256] = now;

  if (fork() == 0) {
    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      _exit(EPERM);
    }

    _exit(execl(kSantaCtlPath, kSantaCtlPath, "sync", "--syslog",
                "singleevent", [event.fileSHA256 UTF8String], NULL));
  }
}

- (santa_action_t)actionForEventState:(SNTEventState)state {
  switch (state) {
    case SNTEventStateAllowBinary:
    case SNTEventStateAllowCertificate:
    case SNTEventStateAllowScope:
    case SNTEventStateAllowUnknown:
      return ACTION_RESPOND_ALLOW;
    case SNTEventStateBlockBinary:
    case SNTEventStateBlockCertificate:
    case SNTEventStateBlockScope:
    case SNTEventStateBlockUnknown:
      return ACTION_RESPOND_DENY;
    default:
      LOGW(@"Invalid event state %ld", state);
      return ACTION_RESPOND_DENY;
  }
}

- (void)printMessage:(NSString *)msg toTTYForPID:(pid_t)pid {
  if (pid < 2) return;  // don't bother even looking for launchd.

  struct proc_bsdinfo taskInfo = {};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0,  &taskInfo, sizeof(taskInfo)) < 1) {
    return;
  }

  // 16-bytes here is for future-proofing. Currently kern.tty.ptmx_max is
  // limited to 999 so 12 bytes should be enough.
  char devPath[16] = "/dev/";
  snprintf(devPath, 16, "/dev/%s", devname(taskInfo.e_tdev, S_IFCHR));
  int fd = open(devPath, O_WRONLY | O_NOCTTY);
  write(fd, msg.UTF8String, msg.length);
  close(fd);
}

- (void)loggedInUsers:(NSArray **)users sessions:(NSArray **)sessions {
  NSMutableDictionary *loggedInUsers = [NSMutableDictionary dictionary];
  NSMutableArray *loggedInHosts = [NSMutableArray array];

  struct utmpx *nxt;
  while ((nxt = getutxent())) {
    if (nxt->ut_type != USER_PROCESS) continue;

    NSString *userName = @(nxt->ut_user);
    NSString *sessionName;
    if (strnlen(nxt->ut_host, 1) > 0) {
      sessionName = [NSString stringWithFormat:@"%@@%s", userName, nxt->ut_host];
    } else {
      sessionName = [NSString stringWithFormat:@"%@@%s", userName, nxt->ut_line];
    }

    if (userName.length) loggedInUsers[userName] = [NSNull null];
    if (sessionName.length) [loggedInHosts addObject:sessionName];
  }
  endutxent();

  *users = [loggedInUsers allKeys];
  *sessions = [loggedInHosts copy];
}

@end
