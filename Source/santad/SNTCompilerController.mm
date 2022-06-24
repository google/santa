/// Copyright 2022 Google Inc. All rights reserved.
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
#include <cstring>
#include <os/base.h>
#include <mach/message.h>

#include <bsm/libbsm.h>

#include <atomic>

#import "Source/common/SNTAllowlistInfo.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommon.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTDatabaseController.h"

using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

static const pid_t PID_MAX = 99999;
static constexpr std::string_view kIgnoredCompilerProcessPathPrefix = "/dev/";

@interface SNTCompilerController () {
  std::atomic<bool> _compilerPIDs[PID_MAX];
}
@end

@implementation SNTCompilerController

- (BOOL)isCompiler:(const audit_token_t&)tok {
  pid_t pid = audit_token_to_pid(tok);
  return pid >= 0 && pid < PID_MAX && self->_compilerPIDs[pid].load();
}

- (void)setIsCompiler:(const audit_token_t&)tok {
  pid_t pid = audit_token_to_pid(tok);
  if (pid < 1) {
    LOGE(@"Unable to watch compiler pid=%d", pid);
  } else if (pid >= PID_MAX) {
    LOGE(@"Unable to watch compiler pid=%d >= PID_MAX(%d)", pid, PID_MAX);
  } else {
    self->_compilerPIDs[pid].store(true);
    LOGD(@"Watching compiler pid=%d", pid);
  }
}

- (void)setNotCompiler:(const audit_token_t&)tok {
  pid_t pid = audit_token_to_pid(tok);
  if (pid && pid < PID_MAX) self->_compilerPIDs[pid].store(false);
}

// Adds a fake cached decision to SNTDecisionCache for pending files. If the file
// is executed before we can create a transitive rule for it, then we can at
// least log the pending decision info.
- (void)saveFakeDecision:(const Message&)esMsg {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.decision = SNTEventStateAllowPendingTransitive;
  cd.vnodeId = {
    .fsid = (uint64_t)esMsg->process->executable->stat.st_dev,
    .fileid = esMsg->process->executable->stat.st_ino
  };
  cd.sha256 = @"pending";
  [[SNTDecisionCache sharedCache] cacheDecision:cd];
}

- (void)removeFakeDecision:(const Message&)esMsg {
  [[SNTDecisionCache sharedCache] forgetCachedDecisionForFile:esMsg->process->executable->stat];
}

- (void)handleEvent:(const Message&)esMsg withLogger:(std::shared_ptr<Logger>)logger {
  switch(esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return;
      }

      if (strncmp(kIgnoredCompilerProcessPathPrefix.data(),
                  esMsg->event.close.target->path.data,
                  kIgnoredCompilerProcessPathPrefix.length()) == 0) {
        return;
      }

      break;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return;
      }

      switch (esMsg->event.rename.destination_type) {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
          if (strncmp(kIgnoredCompilerProcessPathPrefix.data(),
                      esMsg->event.rename.destination.existing_file->path.data,
                      kIgnoredCompilerProcessPathPrefix.length()) == 0) {
              return;
          }
        case ES_DESTINATION_TYPE_NEW_PATH:
          // Note: Sufficient to check the parent directory for the prefix
          if (strncmp(kIgnoredCompilerProcessPathPrefix.data(),
                      esMsg->event.rename.destination.new_path.dir->path.data,
                      kIgnoredCompilerProcessPathPrefix.length()) == 0) {
              return;
          }
        default:
          // Shouldn't happen, means we got bad data from ES...
          return;
      }

      break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      [self setNotCompiler:esMsg->process->audit_token];
      return;
    default:
      return;
  }

  // If we get here, we need to update transitve rules

  [self createTransitiveRule:esMsg withLogger:logger];
}

// Assume that this method is called only when we already know that the writing process is a
// compiler.  It checks if the closed file is executable, and if so, transitively allowlists it.
// The passed in message contains the pid of the writing process and path of closed file.
- (void)createTransitiveRule:(const Message&)esMsg withLogger:(std::shared_ptr<Logger>)logger {
  [self saveFakeDecision:esMsg];

  // Check if this file is an executable.
  SNTFileInfo *fi = [[SNTFileInfo alloc]
      initWithResolvedPath:@(esMsg->process->executable->path.data) error:nil];
  if (fi.isExecutable) {
    // Check if there is an existing (non-transitive) rule for this file.  We leave existing rules
    // alone, so that a allowlist or blocklist rule can't be overwritten by a transitive one.
    SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];
    SNTRule *prevRule = [ruleTable ruleForBinarySHA256:fi.SHA256 certificateSHA256:nil teamID:nil];
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
        logger->LogAllowList(esMsg, [fi.SHA256 UTF8String]);
      }
    }
  }

  // Remove the "pending" decision info from SNTEventLog.
  [self removeFakeDecision:esMsg];
}

@end
