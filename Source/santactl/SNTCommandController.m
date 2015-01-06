/// Copyright 2014 Google Inc. All rights reserved.
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

#import "SNTCommandController.h"

#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@implementation SNTCommandController

/// A dictionary to hold all of the available commands.
/// Key is the name of the command
/// Value is the Class
static NSMutableDictionary *registeredCommands;

+ (void)registerCommand:(Class<SNTCommand>)command named:(NSString *)name {
  if (!registeredCommands) {
    registeredCommands = [NSMutableDictionary dictionary];
  }
  registeredCommands[name] = command;
}

+ (NSString *)usage {
  NSMutableString *helpText = [[NSMutableString alloc] init];

  int longestCommandName = 0;
  for (NSString *cmdName in registeredCommands) {
    if ([cmdName length] > longestCommandName) {
      longestCommandName = (int)[cmdName length];
    }
  }

  for (NSString *cmdName in
       [[registeredCommands allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)]) {
    Class<SNTCommand> cmd = registeredCommands[cmdName];
    [helpText appendFormat:@"\t%*s - %@\n", longestCommandName,
                           [cmdName UTF8String], [cmd shortHelpText]];
  }

  [helpText appendFormat:@"\nSee 'santactl help <command>' to read about a specific subcommand."];
  return helpText;
}

+ (NSString *)helpForCommandWithName:(NSString *)commandName {
  Class<SNTCommand> command = registeredCommands[commandName];
  if (command) {
    NSMutableString *helpText = [[NSMutableString alloc] init];
    [helpText appendFormat:@"Help for '%@':\n", commandName];
    [helpText appendString:[command longHelpText]];
    return helpText;
  }
  return nil;
}

+ (SNTXPCConnection *)connectToDaemon {
  // TODO(rah): Re-factor this so that successfully establishing the connection runs the command,
  // instead of having to sleep until the connection is made.

  SNTXPCConnection *daemonConn =
      [[SNTXPCConnection alloc] initClientWithName:[SNTXPCControlInterface serviceId]
                                           options:NSXPCConnectionPrivileged];
  daemonConn.remoteInterface = [SNTXPCControlInterface controlInterface];

  __block int connected = -1;
  daemonConn.acceptedHandler = ^{
      connected = 1;
  };

  daemonConn.rejectedHandler = ^{
      connected = 0;
      printf("The daemon rejected the connection\n");
      exit(1);
  };

  daemonConn.invalidationHandler = ^{
      connected = 0;
      printf("An error occurred communicating with the daemon\n");
      exit(1);
  };

  [daemonConn resume];

  int idx = 10;
  do {
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    --idx;
  } while (connected == -1 && idx > 0);

  if (connected > 0) {
    return daemonConn;
  } else {
    return nil;
  }
}

+ (BOOL)hasCommandWithName:(NSString *)commandName {
  return ([registeredCommands objectForKey:commandName] != nil);
}

+ (int)runCommandWithName:(NSString *)commandName arguments:(NSArray *)arguments {
  Class<SNTCommand> command = registeredCommands[commandName];
  if (command) {
    if ([command requiresRoot] && getuid() != 0) {
      printf("The command '%s' requires root privileges.\n", [commandName UTF8String]);
      return 2;
    }

    if ([(id)command respondsToSelector:@selector(runWithArguments:daemonConnection:)]) {
      [command runWithArguments:arguments daemonConnection:[self connectToDaemon]];
    } else if ([(id)command respondsToSelector:@selector(runWithArguments:)]) {
      [command runWithArguments:arguments];
    } else {
      printf("The command '%s' has not been implemented correctly.\n", [commandName UTF8String]);
    }

    // The command is responsible for quitting.
    [[NSRunLoop mainRunLoop] run];
  }
  return 128;
}

@end
