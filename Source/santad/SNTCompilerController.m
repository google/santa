//
//  SNTCompilerController.m
//  Santa
//
//  Created by Phillip Nguyen on 10/18/17.
//
//

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
@property int kqueue;
@property NSCache *compilerVnodeIds;
@property NSCache *compilerPids;
@property NSOperationQueue *operationQueue;
@end

@implementation SNTCompilerController


- (instancetype)init {
  self = [super init];
  if (self) {
    _compilerVnodeIds = [[NSCache alloc] init];
    _compilerPids = [[NSCache alloc] init];

    [self startKqueueListener];
  }
  return self;
}

- (void)monitorProceess:(int)pid {
  LOGI(@"#### monitoring process %d", pid);
  struct kevent ke;
  EV_SET(&ke, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);

  // Register for event.  NOTE_EXIT means that we'll be notified when this process exits.
  // EV_ONESHOT means that the monitor will be removed after the first event occurs.
  int i = kevent(self.kqueue, &ke, 1, NULL, 0, NULL);
  if (i == -1) {
    LOGI(@"#### kevent registration error");
  }
}

- (void)startKqueueListener {
  // Create new kernel event queue.
  self.kqueue = kqueue();

  // Then start up a separate process to listen on it for events.
  self.operationQueue = [[NSOperationQueue alloc] init];
  [self.operationQueue addOperationWithBlock:^{
    for (;;) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
      struct kevent ke = {0};
#pragma clang diagnostic pop
      int i = kevent(self.kqueue, NULL, 0, &ke, 1, NULL);
      if (i == -1) {
        LOGI(@"#### kqueueListener error");
      }
      if (ke.fflags & NOTE_EXIT) {
        int pid = (int)ke.ident;
        LOGI(@"#### pid %d exited (with status %d)", pid, (int)ke.data);
        [self.compilerPids removeObjectForKey:@(pid)];
      }
    }
  }];
}

- (void)cacheCompilerWithVnodeId:(uint64_t)vnodeId {
  LOGI(@"#### SNTCompilerController caching vnodeID: %llx", vnodeId);
  [self.compilerVnodeIds setObject:@(YES) forKey:@(vnodeId)];
}

- (void)forgetVnodeId:(uint64_t)vnodeId {
  [self.compilerVnodeIds removeObjectForKey:@(vnodeId)];
}

// If the vnode of the executable matches one of the known compiler vnodes,
// then store the pid in our list of compiler pids.  Otherwise, remove the pid
// from our list of compiler pids.

// TODO:
// If we added ACTION_ALLOW_COMPILER to list of santa_action_t enums, then we
// wouldn't need to keep a separate cache of vnode_ids, and instead could just
// look at the passed in message to see if the process was allowed b/c of a
// compiler rule in database.
- (void)cacheExecution:(santa_message_t)message {
  if ([self.compilerVnodeIds objectForKey:@(message.vnode_id)]) {
    [self.compilerPids setObject:@(YES) forKey:@(message.pid)];
    [self monitorProceess:message.pid];
  } else {
    [self.compilerPids removeObjectForKey:@(message.pid)];
  }
}

// Call this method when ever we receive an ACTION_NOTIFY_CLOSE message
// or ACTION_NOTIFY_RENAME message.
// TODO: rename this to something better that actually reflects what it is doing,
// which is whitelisting stuff.
- (void)checkForCompiler:(santa_message_t)message {
  // message contains pid of writing process and path of written file.

  // Handle RENAME and CLOSE actions only.
  char *target = NULL;
  //if (message.action == ACTION_NOTIFY_WRITE) target = message.path;
  if (message.action == ACTION_NOTIFY_CLOSE) target = message.path;
  else if (message.action == ACTION_NOTIFY_RENAME) target = message.newpath;
  else return;

  char processPath[1024] = {0};
  proc_pidpath(message.pid, processPath, 1024);

  if ([self.compilerPids objectForKey:@(message.pid)]) {
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
}
@end
