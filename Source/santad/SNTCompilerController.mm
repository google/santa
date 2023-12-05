/// Copyright 2017-2022 Google Inc. All rights reserved.
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

#import "Source/santad/SNTCompilerController.h"

#include <bsm/libbsm.h>
#include <mach/message.h>
#include <os/base.h>
#include <string.h>

#include <atomic>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

static const pid_t PID_MAX = 99999;
static constexpr std::string_view kIgnoredCompilerProcessPathPrefix = "/dev/";

@interface SNTCompilerController () {
  std::atomic<bool> _compilerPIDs[PID_MAX];
}
@end

@implementation SNTCompilerController

- (BOOL)isCompiler:(const audit_token_t &)tok {
  pid_t pid = audit_token_to_pid(tok);
  return pid >= 0 && pid < PID_MAX && self->_compilerPIDs[pid].load();
}

- (void)setProcess:(const audit_token_t &)tok isCompiler:(bool)isCompiler {
  pid_t pid = audit_token_to_pid(tok);
  if (pid < 1) {
    LOGE(@"Unable to watch compiler pid=%d", pid);
  } else if (pid >= PID_MAX) {
    LOGE(@"Unable to watch compiler pid=%d >= PID_MAX(%d)", pid, PID_MAX);
  } else {
    self->_compilerPIDs[pid].store(isCompiler);
    if (isCompiler) {
      LOGD(@"Watching compiler pid=%d", pid);
    }
  }
}

// Adds a fake cached decision to SNTDecisionCache for pending files. If the file
// is executed before we can create a transitive rule for it, then we can at
// least log the pending decision info.
- (void)saveFakeDecision:(const es_file_t *)esFile {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] initWithEndpointSecurityFile:esFile];
  cd.decision = SNTEventStateAllowPendingTransitive;
  cd.sha256 = @"pending";
  [[SNTDecisionCache sharedCache] cacheDecision:cd];
}

- (void)removeFakeDecision:(const es_file_t *)esFile {
  [[SNTDecisionCache sharedCache] forgetCachedDecisionForFile:esFile->stat];
}

- (BOOL)handleEvent:(const Message &)esMsg withLogger:(std::shared_ptr<Logger>)logger {
  const es_file_t *targetFile = NULL;

  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return NO;
      }

      if (strncmp(kIgnoredCompilerProcessPathPrefix.data(), esMsg->event.close.target->path.data,
                  kIgnoredCompilerProcessPathPrefix.length()) == 0) {
        return NO;
      }

      targetFile = esMsg->event.close.target;

      break;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return NO;
      }

      // Note: For RENAME events, we process the `source`. This is the one
      // that we sould be creating transitive rules for, not the destination.
      if (strncmp(kIgnoredCompilerProcessPathPrefix.data(), esMsg->event.rename.source->path.data,
                  kIgnoredCompilerProcessPathPrefix.length()) == 0) {
        return NO;
      }

      targetFile = esMsg->event.rename.source;

      break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      [self setProcess:esMsg->process->audit_token isCompiler:false];
      return YES;
    default: return NO;
  }

  // If we get here, we need to update transitve rules
  if (targetFile) {
    [self createTransitiveRule:esMsg target:targetFile logger:logger];
    return YES;
  } else {
    return NO;
  }
}

// Assume that this method is called only when we already know that the writing process is a
// compiler.  It checks if the closed file is executable, and if so, transitively allowlists it.
// The passed in message contains the pid of the writing process and path of closed file.
- (void)createTransitiveRule:(const Message &)esMsg
                      target:(const es_file_t *)targetFile
                      logger:(std::shared_ptr<Logger>)logger {
  NSError *error = nil;
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithEndpointSecurityFile:targetFile error:&error];
  if (error) {
    LOGD(@"Unable to create SNTFileInfo while attempting to create transitive rule. Event: %d | "
         @"Path: %@ | Error: %@",
         (int)esMsg->event_type, @(targetFile->path.data), error);
    return;
  }

  [self saveFakeDecision:targetFile];

  // Check if this file is an executable.
  if (fi.isExecutable) {
    // Check if there is an existing (non-transitive) rule for this file.  We leave existing rules
    // alone, so that a allowlist or blocklist rule can't be overwritten by a transitive one.
    SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];
    SNTRule *prevRule = [ruleTable ruleForBinarySHA256:fi.SHA256
                                             signingID:nil
                                     certificateSHA256:nil
                                                teamID:nil];
    if (!prevRule || prevRule.state == SNTRuleStateAllowTransitive) {
      // Construct a new transitive allowlist rule for the executable.
      SNTRule *rule = [[SNTRule alloc] initWithIdentifier:fi.SHA256
                                                    state:SNTRuleStateAllowTransitive
                                                     type:SNTRuleTypeBinary
                                                customMsg:@""];

      // Add the new rule to the rules database.
      NSError *err;
      if (![ruleTable addRules:@[ rule ] cleanSlate:NO error:&err]) {
        LOGE(@"unable to add new transitive rule to database: %@", err.localizedDescription);
      } else {
        logger->LogAllowlist(esMsg, [fi.SHA256 UTF8String]);
      }
    }
  }

  [self removeFakeDecision:targetFile];
}

@end
