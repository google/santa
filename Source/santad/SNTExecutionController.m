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

#import <MOLCodesignChecker/MOLCodesignChecker.h>

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
#import "SNTPolicyProcessor.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"
#import "SNTStoredEvent.h"
#import "SNTSyncdQueue.h"

// A binary is considered large at ~30MB. Large binaries take longer to hash and consequently
// longer to post a decision back to santa-driver. When a binary is considered large santad will
// let santa-driver know it has received its request and is working on a decision. This allows
// santa-driver to relax; it does not have to worry about resending the request due to a timeout.
static size_t kLargeBinarySize = 30 * 1024 * 1024;

@interface SNTExecutionController ()
@property SNTDriverManager *driverManager;
@property SNTEventLog *eventLog;
@property SNTEventTable *eventTable;
@property SNTNotificationQueue *notifierQueue;
@property SNTPolicyProcessor *policyProcessor;
@property SNTRuleTable *ruleTable;
@property SNTSyncdQueue *syncdQueue;

@property dispatch_queue_t eventQueue;
@end

@implementation SNTExecutionController

#pragma mark Initializers

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager
                            ruleTable:(SNTRuleTable *)ruleTable
                           eventTable:(SNTEventTable *)eventTable
                        notifierQueue:(SNTNotificationQueue *)notifierQueue
                           syncdQueue:(SNTSyncdQueue *)syncdQueue
                             eventLog:(SNTEventLog *)eventLog {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierQueue = notifierQueue;
    _syncdQueue = syncdQueue;
    _eventLog = eventLog;
    _policyProcessor = [[SNTPolicyProcessor alloc] initWithRuleTable:_ruleTable];

    _eventQueue = dispatch_queue_create("com.google.santad.event_upload", DISPATCH_QUEUE_SERIAL);

    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[MOLCodesignChecker alloc] initWithSelf];
  }
  return self;
}

#pragma mark Binary Validation

- (void)validateBinaryWithMessage:(santa_message_t)message {
  // Get info about the file. If we can't get this info, allow execution and log an error.
  if (unlikely(message.path == NULL)) {
    LOGE(@"Path for vnode_id is NULL: %llu", message.vnode_id);
    [_driverManager postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:message.vnode_id];
    return;
  }
  NSError *fileInfoError;
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:@(message.path) error:&fileInfoError];
  if (unlikely(!binInfo)) {
    LOGE(@"Failed to read file %@: %@", @(message.path), fileInfoError.localizedDescription);
    [_driverManager postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:message.vnode_id];
    return;
  }

  // PrinterProxy workaround, see description above the method for more details.
  if ([self printerProxyWorkaround:binInfo]) {
    [_driverManager postToKernelAction:ACTION_RESPOND_DENY forVnodeID:message.vnode_id];
    return;
  }

  // If the binary is large let santa-driver know we received the request and we are working on it.
  if (binInfo.fileSize > kLargeBinarySize) {
    LOGD(@"%@ is larger than %zu. Letting santa-driver know we are working on it.",
         binInfo.path, kLargeBinarySize);
    [_driverManager postToKernelAction:ACTION_RESPOND_ACK forVnodeID:message.vnode_id];
  }

  // Get codesigning info about the file.
  NSError *csError;
  MOLCodesignChecker *csInfo =
      [[MOLCodesignChecker alloc] initWithBinaryPath:binInfo.path
                                      fileDescriptor:binInfo.fileHandle.fileDescriptor
                                               error:&csError];
  // Ignore codesigning if there are any errors with the signature.
  if (csError) csInfo = nil;

  // Actually make the decision.
  SNTCachedDecision *cd = [self.policyProcessor decisionForFileInfo:binInfo
                                                         fileSHA256:nil
                                                  certificateSHA256:csInfo.leafCertificate.SHA256];
  cd.certCommonName = csInfo.leafCertificate.commonName;
  cd.vnodeId = message.vnode_id;

  // Formulate an action from the decision
  santa_action_t action =
      (SNTEventStateAllow & cd.decision) ? ACTION_RESPOND_ALLOW : ACTION_RESPOND_DENY;

  // Save decision details for logging the execution later.
  if (action == ACTION_RESPOND_ALLOW) [_eventLog cacheDecision:cd];

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

      if ([[SNTConfigurator configurator] bundlesEnabled] && binInfo.bundle) {
        // If the binary is part of a bundle, find and hash all the related binaries in the bundle.
        // Let the GUI know hashing is needed. Once the hashing is complete the GUI will send a
        // message to santad to perform the upload logic for bundles.
        // See syncBundleEvent:relatedEvents: for more info.
        se.needsBundleHash = YES;
      } else if ([[SNTConfigurator configurator] syncBaseURL]) {
        // So the server has something to show the user straight away, initiate an event
        // upload for the blocked binary rather than waiting for the next sync.
        dispatch_async(_eventQueue, ^{
          [_syncdQueue addEvents:@[se] isFromBundle:NO];
        });
      }

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
          [msg appendFormat:@"More info:\n%@\n\n", detailURL.absoluteString];
        }
        [self printMessage:msg toTTYForPID:message.ppid];

        [_notifierQueue addEvent:se customMessage:cd.customMsg];
      }
    }
  }
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
  NSMutableSet *loggedInUsers = [NSMutableSet set];
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

    if (userName.length) [loggedInUsers addObject:userName];
    if (sessionName.length) [loggedInHosts addObject:sessionName];
  }
  endutxent();

  *users = [loggedInUsers allObjects];
  *sessions = [loggedInHosts copy];
}

@end
