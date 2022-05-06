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

#import "Source/santad/SNTExecutionController.h"

#include <libproc.h>
#include <pwd.h>
#include <utmpx.h>

#include "Source/common/SNTLogging.h"
#include "Source/common/SNTMetricSet.h"

#import <MOLCodesignChecker/MOLCodesignChecker.h>

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/EventProviders/SNTEventProvider.h"
#import "Source/santad/Logs/SNTEventLog.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTPolicyProcessor.h"
#import "Source/santad/SNTSyncdQueue.h"

// A binary is considered large at ~30MB. Large binaries take longer to hash and consequently
// longer to post a decision back to santa-driver. When a binary is considered large santad will
// let santa-driver know it has received its request and is working on a decision. This allows
// santa-driver to relax; it does not have to worry about resending the request due to a timeout.
static size_t kLargeBinarySize = 30 * 1024 * 1024;

@interface SNTExecutionController ()
@property id<SNTEventProvider> eventProvider;
@property SNTEventTable *eventTable;
@property SNTNotificationQueue *notifierQueue;
@property SNTPolicyProcessor *policyProcessor;
@property SNTRuleTable *ruleTable;
@property SNTSyncdQueue *syncdQueue;
@property SNTMetricCounter *events;

@property dispatch_queue_t eventQueue;
@end

@implementation SNTExecutionController

static NSString *const kPrinterProxyPreMonterey =
  (@"/System/Library/Frameworks/Carbon.framework/Versions/Current/"
   @"Frameworks/Print.framework/Versions/Current/Plugins/PrinterProxy.app/"
   @"Contents/MacOS/PrinterProxy");
static NSString *const kPrinterProxyPostMonterey =
  (@"/System/Library/PrivateFrameworks/PrintingPrivate.framework/"
   @"Versions/Current/Plugins/PrinterProxy.app/Contents/MacOS/PrinterProxy");

#pragma mark Initializers

- (instancetype)initWithEventProvider:(id<SNTEventProvider>)eventProvider
                            ruleTable:(SNTRuleTable *)ruleTable
                           eventTable:(SNTEventTable *)eventTable
                        notifierQueue:(SNTNotificationQueue *)notifierQueue
                           syncdQueue:(SNTSyncdQueue *)syncdQueue {
  self = [super init];
  if (self) {
    _eventProvider = eventProvider;
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierQueue = notifierQueue;
    _syncdQueue = syncdQueue;
    _policyProcessor = [[SNTPolicyProcessor alloc] initWithRuleTable:_ruleTable];

    _eventQueue = dispatch_queue_create("com.google.santad.event_upload", DISPATCH_QUEUE_SERIAL);

    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[MOLCodesignChecker alloc] initWithSelf];

    SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
    _events = [metricSet counterWithName:@"/santa/events"
                              fieldNames:@[ @"action_response" ]
                                helpText:@"Events processed by Santa per response"];
  }
  return self;
}

- (void)incrementEventCounters:(SNTEventState)eventType {
  const NSString *eventTypeStr;

  switch (eventType) {
    case SNTEventStateBlockBinary: eventTypeStr = kBlockBinary; break;
    case SNTEventStateAllowBinary: eventTypeStr = kAllowBinary; break;
    case SNTEventStateBlockCertificate: eventTypeStr = kBlockCertificate; break;
    case SNTEventStateAllowCertificate: eventTypeStr = kAllowCertificate; break;
    case SNTEventStateBlockTeamID: eventTypeStr = kBlockTeamID; break;
    case SNTEventStateAllowTeamID: eventTypeStr = kAllowTeamID; break;
    case SNTEventStateBlockScope: eventTypeStr = kBlockScope; break;
    case SNTEventStateAllowScope: eventTypeStr = kAllowScope; break;
    case SNTEventStateBlockUnknown: eventTypeStr = kBlockUnknown; break;
    case SNTEventStateAllowUnknown: eventTypeStr = kAllowUnknown; break;
    case SNTEventStateAllowCompiler: eventTypeStr = kAllowCompiler; break;
    case SNTEventStateAllowTransitive: eventTypeStr = kAllowTransitive; break;
    default: eventTypeStr = kUnknownEventState; break;
  }

  [_events incrementForFieldValues:@[ (NSString *)eventTypeStr ]];
}

#pragma mark Binary Validation

- (void)validateBinaryWithMessage:(santa_message_t)message {
  // Get info about the file. If we can't get this info, allow execution and log an error.
  if (unlikely(message.path == NULL)) {
    LOGE(@"Path for vnode_id is NULL: %llu/%llu", message.vnode_id.fsid, message.vnode_id.fileid);
    [self.eventProvider postAction:ACTION_RESPOND_ALLOW forMessage:message];
    [self.events incrementForFieldValues:@[ (NSString *)kAllowNullVNode ]];
    return;
  }

  SNTConfigurator *config = [SNTConfigurator configurator];

  NSError *fileInfoError;
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:@(message.path) error:&fileInfoError];
  if (unlikely(!binInfo)) {
    LOGE(@"Failed to read file %@: %@", @(message.path), fileInfoError.localizedDescription);
    if (config.failClosed && config.clientMode == SNTClientModeLockdown) {
      [self.eventProvider postAction:ACTION_RESPOND_DENY forMessage:message];
      [self.events incrementForFieldValues:@[ (NSString *)kDenyNoFileInfo ]];
    } else {
      [self.eventProvider postAction:ACTION_RESPOND_ALLOW forMessage:message];
      [self.events incrementForFieldValues:@[ (NSString *)kAllowNoFileInfo ]];
    }
    return;
  }

  // PrinterProxy workaround, see description above the method for more details.
  if ([self printerProxyWorkaround:binInfo]) {
    [self.eventProvider postAction:ACTION_RESPOND_DENY forMessage:message];
    [self.events incrementForFieldValues:@[ (NSString *)kBlockPrinterWorkaround ]];
    return;
  }

  // If the binary is large let santa-driver know we received the request and we are working on it.
  if (binInfo.fileSize > kLargeBinarySize) {
    LOGD(@"%@ is larger than %zu. Letting santa-driver know we are working on it.", binInfo.path,
         kLargeBinarySize);
    [self.eventProvider postAction:ACTION_RESPOND_ACK forMessage:message];
    // TODO(markowsky): Maybe add a metric here for how many large executables we're seeing.
  }

  SNTCachedDecision *cd = [self.policyProcessor decisionForFileInfo:binInfo];
  cd.vnodeId = message.vnode_id;

  // Formulate an initial action from the decision.
  santa_action_t action =
    (SNTEventStateAllow & cd.decision) ? ACTION_RESPOND_ALLOW : ACTION_RESPOND_DENY;

  // Save decision details for logging the execution later.  For transitive rules, we also use
  // the shasum stored in the decision details to update the rule's timestamp whenever an
  // ACTION_NOTIFY_EXEC message related to the transitive rule is received.
  NSString *ttyPath;
  if (action == ACTION_RESPOND_ALLOW) {
    [[SNTEventLog logger] cacheDecision:cd];
  } else {
    ttyPath = @(message.ttypath);
  }

  // Upgrade the action to ACTION_RESPOND_ALLOW_COMPILER when appropriate, because we want the
  // kernel to track this information in its decision cache.
  if (cd.decision == SNTEventStateAllowCompiler) {
    action = ACTION_RESPOND_ALLOW_COMPILER;
  }

  // Send the decision to the kernel.
  [self.eventProvider postAction:action forMessage:message];

  // Increment counters;
  [self incrementEventCounters:cd.decision];

  // Log to database if necessary.
  if ([SNTConfigurator configurator].enableAllEventUpload ||
      (cd.decision != SNTEventStateAllowBinary && cd.decision != SNTEventStateAllowCompiler &&
       cd.decision != SNTEventStateAllowTransitive &&
       cd.decision != SNTEventStateAllowCertificate && cd.decision != SNTEventStateAllowTeamID &&
       cd.decision != SNTEventStateAllowScope)) {
    SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
    se.occurrenceDate = [[NSDate alloc] init];
    se.fileSHA256 = cd.sha256;
    se.filePath = binInfo.path;
    se.decision = cd.decision;

    se.signingChain = cd.certChain;
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

    // Only store events if there is a sync server configured.
    if (config.syncBaseURL) {
      dispatch_async(_eventQueue, ^{
        [self.eventTable addStoredEvent:se];
      });
    }

    // If binary was blocked, do the needful
    if (action != ACTION_RESPOND_ALLOW && action != ACTION_RESPOND_ALLOW_COMPILER) {
      [[SNTEventLog logger] logDeniedExecution:cd withMessage:message];

      if (config.enableBundles && binInfo.bundle) {
        // If the binary is part of a bundle, find and hash all the related binaries in the bundle.
        // Let the GUI know hashing is needed. Once the hashing is complete the GUI will send a
        // message to santad to perform the upload logic for bundles.
        // See syncBundleEvent:relatedEvents: for more info.
        se.needsBundleHash = YES;
      } else if (config.syncBaseURL) {
        // So the server has something to show the user straight away, initiate an event
        // upload for the blocked binary rather than waiting for the next sync.
        dispatch_async(_eventQueue, ^{
          [self.syncdQueue addEvents:@[ se ] isFromBundle:NO];
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
        if (ttyPath) [self printMessage:msg toTTY:ttyPath];

        [self.notifierQueue addEvent:se customMessage:cd.customMsg];
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

  @param fi SNTFileInfo object for the binary being executed.
  @return YES if the workaround was applied, NO otherwise.
*/
- (BOOL)printerProxyWorkaround:(SNTFileInfo *)fi {
  if ([fi.path hasSuffix:@"/Contents/MacOS/PrinterProxy"] &&
      [fi.path containsString:@"Library/Printers"]) {
    SNTFileInfo *proxyFi = [self printerProxyFileInfo];
    if ([proxyFi.SHA256 isEqual:fi.SHA256]) return NO;

    NSFileHandle *inFh = [NSFileHandle fileHandleForReadingAtPath:proxyFi.path];
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
  Returns an SNTFileInfo for the system PrinterProxy path on this system.
*/
- (SNTFileInfo *)printerProxyFileInfo {
  SNTFileInfo *proxyInfo = [[SNTFileInfo alloc] initWithPath:kPrinterProxyPostMonterey];
  if (!proxyInfo) proxyInfo = [[SNTFileInfo alloc] initWithPath:kPrinterProxyPreMonterey];
  return proxyInfo;
}

- (void)printMessage:(NSString *)msg toTTY:(NSString *)path {
  int fd = open(path.UTF8String, O_WRONLY | O_NOCTTY);
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
