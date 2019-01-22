/// Copyright 2015 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#import "Source/santactl/SNTCommandController.h"

///
///  santactl is a command-line utility for managing Santa.
///  As it can be used for a number of distinct operations, its operation is split into different
///  'commands' which are expected to be the first argument to the binary. The main function below
///  is simply responsible for either passing control to the specified command or printing a useful
///  usage string.
///

void print_usage() {
  printf("Usage: santactl:\n%s\n", [[SNTCommandController usage] UTF8String]);
}

void print_unknown_command(NSString *commandName) {
  printf("Unknown command: %s\n", [commandName UTF8String]);
}

void print_string(NSString *string) {
  printf("%s\n", [string UTF8String]);
}

int main(int argc, const char *argv[]) {
  // Do not buffer stdout
  setbuf(stdout, NULL);

  @autoreleasepool {
    NSMutableArray *arguments = [[[NSProcessInfo processInfo] arguments] mutableCopy];
    [arguments removeObjectAtIndex:0];

    NSString *commandName = [arguments firstObject];
    if (!commandName ||
        [commandName isEqualToString:@"usage"] ||
        [commandName isEqualToString:@"commands"]) {
      print_usage();
      return 1;
    }
    [arguments removeObjectAtIndex:0];

    if ([commandName isEqualToString:@"help"] ||
        [commandName isEqualToString:@"-h"] ||
        [commandName isEqualToString:@"--help"]) {
      if ([arguments count]) {
        // User wants help for specific command
        commandName = [arguments firstObject];
        if (![SNTCommandController hasCommandWithName:commandName]) {
          print_unknown_command(commandName);
          return 1;
        } else {
          print_string([SNTCommandController helpForCommandWithName:commandName]);
          return 1;
        }
      } else {
        // User generally wants help
        print_usage();
        return 0;
      }
    }

    // User knows what command they want, does it exist?
    if (![SNTCommandController hasCommandWithName:commandName]) {
      print_unknown_command(commandName);
      return 128;
    }

    [SNTCommandController runCommandWithName:commandName arguments:arguments];
  }
}
