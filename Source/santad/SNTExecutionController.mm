
/// Copyright 2015-2022 Google Inc. All rights reserved.
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
#include <Foundation/Foundation.h>

#import <MOLCodesignChecker/MOLCodesignChecker.h>
#include <bsm/libbsm.h>
#include <copyfile.h>
#include <libproc.h>
#include <pwd.h>
#include <sys/param.h>
#include <utmpx.h>

#include <memory>
#include <set>
#include <string>

#include "Source/common/BranchPrediction.h"
#include "Source/common/PrefixTree.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeepCopy.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/String.h"
#include "Source/common/Unit.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTPolicyProcessor.h"
#import "Source/santad/SNTSyncdQueue.h"
#include "absl/synchronization/mutex.h"

using santa::common::PrefixTree;
using santa::common::Unit;
using santa::santad::TTYWriter;
using santa::santad::event_providers::endpoint_security::Message;

static const size_t kMaxAllowedPathLength = MAXPATHLEN - 1;  // -1 to account for null terminator

void UpdateTeamIDFilterLocked(std::set<std::string> &filterSet, NSArray<NSString *> *filter) {
  filterSet.clear();

  for (NSString *prefix in filter) {
    filterSet.insert(santa::common::NSStringToUTF8String(prefix));
  }
}

void UpdatePrefixFilterLocked(std::unique_ptr<PrefixTree<Unit>> &tree,
                              NSArray<NSString *> *filter) {
  tree->Reset();

  for (NSString *item in filter) {
    tree->InsertPrefix(item.UTF8String, Unit{});
  }
}

@interface SNTExecutionController ()
@property SNTEventTable *eventTable;
@property SNTNotificationQueue *notifierQueue;
@property SNTPolicyProcessor *policyProcessor;
@property SNTRuleTable *ruleTable;
@property SNTSyncdQueue *syncdQueue;
@property SNTMetricCounter *events;

@property dispatch_queue_t eventQueue;
@end

@implementation SNTExecutionController {
  std::shared_ptr<TTYWriter> _ttyWriter;
  absl::Mutex _entitlementFilterMutex;
  std::set<std::string> _entitlementsTeamIDFilter;
  std::unique_ptr<PrefixTree<Unit>> _entitlementsPrefixFilter;
}

static NSString *const kPrinterProxyPreMonterey =
  (@"/System/Library/Frameworks/Carbon.framework/Versions/Current/"
   @"Frameworks/Print.framework/Versions/Current/Plugins/PrinterProxy.app/"
   @"Contents/MacOS/PrinterProxy");
static NSString *const kPrinterProxyPostMonterey =
  (@"/System/Library/PrivateFrameworks/PrintingPrivate.framework/"
   @"Versions/Current/Plugins/PrinterProxy.app/Contents/MacOS/PrinterProxy");

#pragma mark Initializers

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable
                       eventTable:(SNTEventTable *)eventTable
                    notifierQueue:(SNTNotificationQueue *)notifierQueue
                       syncdQueue:(SNTSyncdQueue *)syncdQueue
                        ttyWriter:(std::shared_ptr<TTYWriter>)ttyWriter
         entitlementsPrefixFilter:(NSArray<NSString *> *)entitlementsPrefixFilter
         entitlementsTeamIDFilter:(NSArray<NSString *> *)entitlementsTeamIDFilter {
  self = [super init];
  if (self) {
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierQueue = notifierQueue;
    _syncdQueue = syncdQueue;
    _ttyWriter = std::move(ttyWriter);
    _policyProcessor = [[SNTPolicyProcessor alloc] initWithRuleTable:_ruleTable];

    _eventQueue =
      dispatch_queue_create("com.google.santa.daemon.event_upload", DISPATCH_QUEUE_SERIAL);

    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[MOLCodesignChecker alloc] initWithSelf];

    SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
    _events = [metricSet counterWithName:@"/santa/events"
                              fieldNames:@[ @"action_response" ]
                                helpText:@"Events processed by Santa per response"];

    self->_entitlementsPrefixFilter = std::make_unique<PrefixTree<Unit>>();

    UpdatePrefixFilterLocked(self->_entitlementsPrefixFilter, entitlementsPrefixFilter);
    UpdateTeamIDFilterLocked(self->_entitlementsTeamIDFilter, entitlementsTeamIDFilter);
  }
  return self;
}

- (void)updateEntitlementsPrefixFilter:(NSArray<NSString *> *)filter {
  absl::MutexLock lock(&self->_entitlementFilterMutex);
  UpdatePrefixFilterLocked(self->_entitlementsPrefixFilter, filter);
}

- (void)updateEntitlementsTeamIDFilter:(NSArray<NSString *> *)filter {
  absl::MutexLock lock(&self->_entitlementFilterMutex);
  UpdateTeamIDFilterLocked(self->_entitlementsTeamIDFilter, filter);
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
    case SNTEventStateBlockSigningID: eventTypeStr = kBlockSigningID; break;
    case SNTEventStateAllowSigningID: eventTypeStr = kAllowSigningID; break;
    case SNTEventStateBlockScope: eventTypeStr = kBlockScope; break;
    case SNTEventStateAllowScope: eventTypeStr = kAllowScope; break;
    case SNTEventStateBlockUnknown: eventTypeStr = kBlockUnknown; break;
    case SNTEventStateAllowUnknown: eventTypeStr = kAllowUnknown; break;
    case SNTEventStateAllowCompiler: eventTypeStr = kAllowCompiler; break;
    case SNTEventStateAllowTransitive: eventTypeStr = kAllowTransitive; break;
    case SNTEventStateBlockLongPath: eventTypeStr = kBlockLongPath; break;
    default: eventTypeStr = kUnknownEventState; break;
  }

  [_events incrementForFieldValues:@[ (NSString *)eventTypeStr ]];
}

#pragma mark Binary Validation

- (bool)synchronousShouldProcessExecEvent:(const Message &)esMsg {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    // Programming error. Bail.
    LOGE(@"Attempt to validate non-EXEC event. Event type: %d", esMsg->event_type);
    [NSException
       raise:@"Invalid event type"
      format:@"synchronousShouldProcessExecEvent: Unexpected event type: %d", esMsg->event_type];
  }

  const es_process_t *targetProc = esMsg->event.exec.target;

  if (targetProc->executable->path.length > kMaxAllowedPathLength ||
      targetProc->executable->path_truncated) {
    // Store a SNTCachedDecision so that this event gets properly logged
    SNTCachedDecision *cd =
      [[SNTCachedDecision alloc] initWithEndpointSecurityFile:targetProc->executable];
    cd.decision = SNTEventStateBlockLongPath;
    cd.customMsg = [NSString stringWithFormat:@"Path exceeded max length for processing (%zu)",
                                              targetProc->executable->path.length];

    if (targetProc->team_id.data) {
      cd.teamID = [NSString stringWithUTF8String:targetProc->team_id.data];
    }

    // TODO(mlw): We should be able to grab signing info to have more-enriched log messages in the
    // future. The code to do this should probably be abstracted from the SNTPolicyProcessor.

    [[SNTDecisionCache sharedCache] cacheDecision:cd];

    return NO;
  }

  // An SNTCachedDecision will be created later on during full processing
  return YES;
}

- (void)validateExecEvent:(const Message &)esMsg postAction:(bool (^)(SNTAction))postAction {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    // Programming error. Bail.
    LOGE(@"Attempt to validate non-EXEC event. Event type: %d", esMsg->event_type);
    [NSException
       raise:@"Invalid event type"
      format:@"validateExecEvent:postAction: Unexpected event type: %d", esMsg->event_type];
  }

  // Get info about the file. If we can't get this info, respond appropriately and log an error.
  SNTConfigurator *config = [SNTConfigurator configurator];
  const es_process_t *targetProc = esMsg->event.exec.target;

  NSError *fileInfoError;
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithEndpointSecurityFile:targetProc->executable
                                                                     error:&fileInfoError];
  if (unlikely(!binInfo)) {
    if (config.failClosed && config.clientMode == SNTClientModeLockdown) {
      LOGE(@"Failed to read file %@: %@ and denying action", @(targetProc->executable->path.data),
           fileInfoError.localizedDescription);
      postAction(SNTActionRespondDeny);
      [self.events incrementForFieldValues:@[ (NSString *)kDenyNoFileInfo ]];
    } else {
      LOGE(@"Failed to read file %@: %@ but allowing action", @(targetProc->executable->path.data),
           fileInfoError.localizedDescription);
      postAction(SNTActionRespondAllow);
      [self.events incrementForFieldValues:@[ (NSString *)kAllowNoFileInfo ]];
    }
    return;
  }

  // PrinterProxy workaround, see description above the method for more details.
  if ([self printerProxyWorkaround:binInfo]) {
    postAction(SNTActionRespondDeny);
    [self.events incrementForFieldValues:@[ (NSString *)kBlockPrinterWorkaround ]];
    return;
  }

  // TODO(markowsky): Maybe add a metric here for how many large executables we're seeing.
  // if (binInfo.fileSize > SomeUpperLimit) ...

  SNTCachedDecision *cd = [self.policyProcessor
           decisionForFileInfo:binInfo
                 targetProcess:targetProc
    entitlementsFilterCallback:^NSDictionary *(const char *teamID, NSDictionary *entitlements) {
      if (!entitlements) {
        return nil;
      }

      absl::ReaderMutexLock lock(&self->_entitlementFilterMutex);

      if (teamID && self->_entitlementsTeamIDFilter.count(std::string(teamID)) > 0) {
        LOGD(@"Dropping entitlement logging for configured TeamID: %s", teamID);
        return nil;
      }

      if (self->_entitlementsPrefixFilter->NodeCount() == 0) {
        LOGD(@"Copying full entitlements for tid: %s", teamID);
        return [entitlements sntDeepCopy];
      } else {
        LOGD(@"Filtering entitlements for tid: %s", teamID);
        NSMutableDictionary *filtered = [NSMutableDictionary dictionary];

        [entitlements enumerateKeysAndObjectsUsingBlock:^(NSString *key, id obj, BOOL *stop) {
          if (!self->_entitlementsPrefixFilter->HasPrefix(key.UTF8String)) {
            if ([obj isKindOfClass:[NSArray class]] || [obj isKindOfClass:[NSDictionary class]]) {
              [filtered setObject:[obj sntDeepCopy] forKey:key];
            } else {
              [filtered setObject:[obj copy] forKey:key];
            }
          }
        }];

        return filtered.count > 0 ? filtered : nil;
      }
    }];

  cd.vnodeId = SantaVnode::VnodeForFile(targetProc->executable);

  // Formulate an initial action from the decision.
  SNTAction action =
    (SNTEventStateAllow & cd.decision) ? SNTActionRespondAllow : SNTActionRespondDeny;

  // Save decision details for logging the execution later.  For transitive rules, we also use
  // the shasum stored in the decision details to update the rule's timestamp whenever an
  // ACTION_NOTIFY_EXEC message related to the transitive rule is received.
  [[SNTDecisionCache sharedCache] cacheDecision:cd];

  // Upgrade the action to SNTActionRespondAllowCompiler when appropriate, because we want the
  // kernel to track this information in its decision cache.
  if (cd.decision == SNTEventStateAllowCompiler) {
    action = SNTActionRespondAllowCompiler;
  }

  // Respond with the decision.
  postAction(action);

  // Increment metric counters
  [self incrementEventCounters:cd.decision];

  // Log to database if necessary.
  if (config.enableAllEventUpload ||
      (cd.decision == SNTEventStateAllowUnknown && !config.disableUnknownEventUpload) ||
      (cd.decision & SNTEventStateAllow) == 0) {
    SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
    se.occurrenceDate = [[NSDate alloc] init];
    se.fileSHA256 = cd.sha256;
    se.filePath = binInfo.path;
    se.decision = cd.decision;

    se.signingChain = cd.certChain;
    se.teamID = cd.teamID;
    se.signingID = cd.signingID;
    se.pid = @(audit_token_to_pid(targetProc->audit_token));
    se.ppid = @(audit_token_to_pid(targetProc->parent_audit_token));
    se.parentName = @(esMsg.ParentProcessName().c_str());

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
    struct passwd *user = getpwuid(audit_token_to_ruid(targetProc->audit_token));
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
    if (action != SNTActionRespondAllow && action != SNTActionRespondAllowCompiler) {
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
        if (!config.enableSilentTTYMode && self->_ttyWriter && TTYWriter::CanWrite(targetProc)) {
          // Let the user know what happened on the terminal
          NSAttributedString *s = [SNTBlockMessage attributedBlockMessageForEvent:se
                                                                    customMessage:cd.customMsg];

          NSMutableString *msg = [NSMutableString stringWithCapacity:1024];
          // Escape sequences `\033[1m` and `\033[0m` begin/end bold lettering
          [msg appendFormat:@"\n\033[1mSanta\033[0m\n\n%@\n\n", s.string];
          [msg appendFormat:@"\033[1mPath:      \033[0m %@\n"
                            @"\033[1mIdentifier:\033[0m %@\n"
                            @"\033[1mParent:    \033[0m %@ (%@)\n\n",
                            se.filePath, se.fileSHA256, se.parentName, se.ppid];
          NSURL *detailURL = [SNTBlockMessage eventDetailURLForEvent:se customURL:cd.customURL];
          if (detailURL) {
            [msg appendFormat:@"More info:\n%@\n\n", detailURL.absoluteString];
          }

          self->_ttyWriter->Write(targetProc, msg);
        }

        // Let the user know what happened in the GUI.
        [self.notifierQueue addEvent:se withCustomMessage:cd.customMsg andCustomURL:cd.customURL];
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

    copyfile_flags_t copyflags = COPYFILE_ALL | COPYFILE_UNLINK;
    if (copyfile(proxyFi.path.UTF8String, fi.path.UTF8String, NULL, copyflags) != 0) {
      LOGE(@"Failed to apply PrinterProxy workaround for %@", fi.path);
    } else {
      LOGI(@"PrinterProxy workaround applied to: %@", fi.path);
    }

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
