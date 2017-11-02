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


// Return parent of given pid.  If pid has no parent, returns itself.
int ppid(int pid) {
  struct proc_bsdinfo info;
  proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
  return info.pbi_ppid;
}

// Sometimes we get a pid after it's process is already gone, in which case this
// will return 0.
uint64_t vnodeIDForPid(int pid) {
  char path[1024];
  proc_pidpath(pid, path, 1024);

  struct stat fstat = {};
  stat(path, &fstat);
  return (((uint64_t)fstat.st_dev << 32) | fstat.st_ino);
}

NSString *stringForAction(santa_action_t action) {
  switch(action) {
      case ACTION_NOTIFY_EXEC: return @"EXEC";
      case ACTION_NOTIFY_WRITE: return @"WRITE";
      case ACTION_NOTIFY_RENAME: return @"RENAME";
      case ACTION_NOTIFY_LINK: return @"LINK";
      case ACTION_NOTIFY_EXCHANGE: return @"EXCHANGE";
      case ACTION_NOTIFY_DELETE: return @"DELETE";
      case ACTION_NOTIFY_OPEN: return @"OPEN";
      case ACTION_NOTIFY_CLOSE: return @"CLOSE";
      default: return @"UNKNOWN";
  }
}

@interface SNTCompilerController()
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
    // create new kernel event queue
    _kq = kqueue();
    _operationQueue = [[NSOperationQueue alloc] init];
    [self kqueueListener];
  }
  return self;
}

- (void)monitorProceess:(int)pid {
  LOGI(@"#### monitoring process %d", pid);
  struct kevent ke;
  //EV_SET(&ke, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT | NOTE_FORK | NOTE_EXEC, 0, NULL);
  EV_SET(&ke, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);

  // register for event
  int i = kevent(_kq, &ke, 1, NULL, 0, NULL);
  if (i == -1) {
    LOGI(@"#### kevent registration error");
  }
}

- (void)kqueueListener {
  [self.operationQueue addOperationWithBlock:^{
    for (;;) {
      // Listen for events in an infinite loop.
      struct kevent ke = {0};
      int i = kevent(_kq, NULL, 0, &ke, 1, NULL);
      if (i == -1) {
        LOGI(@"#### kqueueListener error");
      }
      if (ke.fflags & NOTE_EXIT) {
        int pid = (int)ke.ident;
        LOGI(@"#### pid %d exited (with status %d)", pid, (int)ke.data);
        [self.compilerPids removeObjectForKey:@(pid)];
        // also should stop monitoring this pid by sending a EV_DELETE message to kevent.
        // alternatively, pass EV_ONESHOT when setting up the original monitor.
      }
      /*
      if (ke.fflags & NOTE_FORK) {
        LOGI(@"#### pid %d forked (%ld)", (int)ke.ident, ke.data);
      }
      if (ke.fflags & NOTE_CHILD) {
        LOGI(@"#### pid %d has %d as parent", (int)ke.ident, (int)ke.data);
      }
      if (ke.fflags & NOTE_EXEC) {
        LOGI(@"#### pid %d called exec", (int)ke.ident);
      }
       */
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
// from our list of compiler pids.  This is called for every execution so we
// should normally be aware of which pid is a compiler and which is not, except
// if pid is forked process that reuses an older pid that was never replaced.
// hmm.

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
  // TODO: remove
  /*
  // this seems to be unneeded.
  else {
    // Look for an ancestor process that is a compiler.
    pid_t pid = message.pid;
    pid_t parent = ppid(pid);
    while (pid != parent) {
      if ([self.compilerPids objectForKey:@(pid)]) {
        LOGI(@"#### SNTCompilerController found ancestor compiler process");
        break;
      }
      pid = parent;
      parent = ppid(pid);
    }
  }
  */

}
@end
