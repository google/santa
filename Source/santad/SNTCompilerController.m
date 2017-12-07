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
#import "SNTDriverManager.h"
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
@property NSOperationQueue *operationQueue;
@property SNTDriverManager *driverManager;
@end

@implementation SNTCompilerController


- (instancetype)initWithDriverManager:(id)driverManager {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
    [self startKqueueListener];
  }
  return self;
}

// Given the pid of a compiler process, registers an event with the kqueue so that we'll be
// notified when the process terminates.
// TODO: Should we have error checking on the pid value?  Presumably pid 0 would never be a
// compiler. maybe even restrict all pids < threshold.
- (void)monitorCompilerProcess:(pid_t)pid {
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

// This runs an infinite loop in a separate thread so that we can listen for kqueue events related
// to process termination.  Whenever a compiler process terminates, it sends a message back to the
// kernel to notify it.
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
        [self.driverManager processTerminated:pid];
      }
    }
  }];
}

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
