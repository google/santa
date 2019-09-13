/// Copyright 2017 Google Inc. All rights reserved.
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

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTKernelCommon.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTEventProvider.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/Logs/SNTEventLog.h"

@interface SNTCompilerController ()
@property id<SNTEventProvider> eventProvider;
@property SNTEventLog *eventLog;
@end

@implementation SNTCompilerController

- (instancetype)initWithEventProvider:(id<SNTEventProvider>)eventProvider
                             eventLog:(SNTEventLog *)eventLog {
  self = [super init];
  if (self) {
    _eventProvider = eventProvider;
    _eventLog = eventLog;
  }
  return self;
}

// Adds a fake cached decision to SNTEventLog for pending files.  If the file
// is executed before we can create a transitive rule for it, then we can at
// least log the pending decision info.
- (void)saveFakeDecision:(santa_message_t)message {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.decision = SNTEventStateAllowPendingTransitive;
  cd.vnodeId = message.vnode_id;
  cd.sha256 = @"pending";
  [self.eventLog cacheDecision:cd];
}

- (void)removeFakeDecision:(santa_message_t)message {
  [self.eventLog forgetCachedDecisionForVnodeId:message.vnode_id];
}

// Assume that this method is called only when we already know that the writing process is a
// compiler.  It checks if the closed file is executable, and if so, transitively whitelists it.
// The passed in message contains the pid of the writing process and path of closed file.
- (void)createTransitiveRule:(santa_message_t)message {
  [self saveFakeDecision:message];

  char *target = message.path;

  // Check if this file is an executable.
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@(target)];
  if (fi.isExecutable) {
    // Check if there is an existing (non-transitive) rule for this file.  We leave existing rules
    // alone, so that a whitelist or blacklist rule can't be overwritten by a transitive one.
    SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];
    SNTRule *prevRule = [ruleTable ruleForBinarySHA256:fi.SHA256 certificateSHA256:nil];
    if (!prevRule || prevRule.state == SNTRuleStateWhitelistTransitive) {
      // Construct a new transitive whitelist rule for the executable.
      SNTRule *rule = [[SNTRule alloc] initWithShasum:fi.SHA256
                                                state:SNTRuleStateWhitelistTransitive
                                                 type:SNTRuleTypeBinary
                                            customMsg:@""];

      // Add the new rule to the rules database.
      NSError *err;
      if (![ruleTable addRules:@[ rule ] cleanSlate:NO error:&err]) {
        LOGE(@"unable to add new transitive rule to database: %@", err.localizedDescription);
      } else {
        [self.eventLog
            writeLog:[NSString stringWithFormat:@"action=WHITELIST|pid=%d|path=%s|sha256=%@",
                                                message.pid, target, fi.SHA256]];
      }
    }
  }

  // Remove the temporary allow rule in the kernel decision cache.
  [self.eventProvider removeCacheEntryForVnodeID:message.vnode_id];
  // Remove the "pending" decision info from SNTEventLog.
  [self removeFakeDecision:message];
}

@end
