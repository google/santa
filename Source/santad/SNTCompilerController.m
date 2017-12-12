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

#import "SNTCompilerController.h"

#import "SNTCommonEnums.h"
#import "SNTDatabaseController.h"
#import "SNTFileInfo.h"
#import "SNTKernelCommon.h"
#import "SNTLogging.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"


@implementation SNTCompilerController

// Assume that this method is called only when we already know that the writing process is a
// compiler.  It checks if the closed file is executable, and if so, transitively whitelists it.
// The passed in message contains the pid of the writing process and path of closed file.
- (void)checkForNewExecutable:(santa_message_t)message {
  // Handle CLOSE actions only.
  if (message.action != ACTION_NOTIFY_CLOSE) return;
  char *target = message.path;

  // Check if this file is an executable.
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@(target)];
  if (fi.isExecutable) {
    // Check if there is an existing (non-transitive) rule for this file.  We leave existing rules
    // alone, so that a whitelist or blacklist rule can't be overwritten by a transitive one.
    SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];
    SNTRule *prevRule = [ruleTable ruleForBinarySHA256:fi.SHA1 certificateSHA256:nil];
    if (prevRule && prevRule.state != SNTRuleStateWhitelistTransitive) {
      LOGI(@"#### found existing rule for %@, not adding transitive rule", fi.path);
      return;
    }

    // Construct a new transitive whitelist rule for the executable.
    SNTRule *rule = [[SNTRule alloc] initWithShasum:fi.SHA256
                                              state:SNTRuleStateWhitelistTransitive
                                               type:SNTRuleTypeBinary
                                          customMsg:@""];

    // Add the new rule to the rules database.
    NSError *err = [[NSError alloc] init];
    if (![ruleTable addRules:@[rule] cleanSlate:NO error:&err]) {
      LOGE(@"#### SNTCompilerController: error adding new rule: %@", err.localizedDescription);
    } else {
      LOGI(@"#### SNTCompilerController: CLOSE %d new whitelisted executable %s (SHA=%@)",
           message.pid, target, fi.SHA256);
    }
  }
}

@end
