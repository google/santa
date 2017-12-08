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

#import <libproc.h>
#import <sys/stat.h>
#import <sys/event.h>
#import "SNTCommonEnums.h"
#import "SNTCompilerController.h"
#import "SNTDatabaseController.h"
#import "SNTFileInfo.h"
#import "SNTKernelCommon.h"
#import "SNTLogging.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"


// TODO: remove this
NSString *stringForAction(santa_action_t action) {
  switch(action) {
      case ACTION_NOTIFY_EXEC: return @"EXEC";
      case ACTION_NOTIFY_WRITE: return @"WRITE";
      case ACTION_NOTIFY_RENAME: return @"RENAME";
      case ACTION_NOTIFY_LINK: return @"LINK";
      case ACTION_NOTIFY_EXCHANGE: return @"EXCHANGE";
      case ACTION_NOTIFY_DELETE: return @"DELETE";
      case ACTION_NOTIFY_CLOSE: return @"CLOSE";
      default: return @"UNKNOWN";
  }
}

@interface SNTCompilerController()
@end

@implementation SNTCompilerController

// Assume that this method is called only when we already know that the writing process is a
// compiler.  It checks if the written / renamed file is executable, and if so, transitively
// whitelists it.
- (void)checkForNewExecutable:(santa_message_t)message {
  // message contains pid of writing process and path of written file.

  // Handle RENAME and CLOSE actions only.
  char *target = NULL;
  if (message.action == ACTION_NOTIFY_CLOSE) target = message.path;
  else if (message.action == ACTION_NOTIFY_RENAME) target = message.newpath;
  else return;

  char processPath[1024] = {0};
  proc_pidpath(message.pid, processPath, 1024);

  // Check if this file is an executable.
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@(target)];
  if (fi.isExecutable) {
    // Construct a new rule for this file.
    SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];
    SNTRule *rule = [[SNTRule alloc] initWithShasum:fi.SHA256
                                              state:SNTRuleStateWhitelistTransitive
                                               type:SNTRuleTypeBinary
                                          customMsg:@""];
    NSError *err = [[NSError alloc] init];
    if (![ruleTable addRules:@[rule] cleanSlate:NO error:&err]) {
      LOGI(@"#### SNTCompilerController: error adding new rule: %@", err.localizedDescription);
    } else {
      LOGI(@"#### SNTCompilerController: %@ %d new whitelisted executable %s (SHA=%@)",
           stringForAction(message.action), message.pid, target, fi.SHA256);
    }
  }
}

@end
