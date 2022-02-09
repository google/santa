/// Copyright 2021 Google Inc. All rights reserved.
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

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <getopt.h>
#import <stdlib.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santad/EventProviders/EndpointSecurityTestUtil.h"
#import "Source/santad/Logs/SNTFileEventLog.h"
#import "Source/santad/Logs/SNTProtobufEventLog.h"
#import "Source/santad/Logs/SNTSyslogEventLog.h"

@interface SNTConfigurator(Testing)
@property NSMutableDictionary *configState;
@end

void usage(void)
{
  fprintf(stderr, "Usage: %s [-i <iterations>] [-l (file|syslog|protobuf)]\n",
      getprogname());
}

void runLogFileModification(santa_message_t *msg, SNTEventLog *eventLog)
{
  msg->action = ACTION_NOTIFY_RENAME;
  [eventLog logFileModification:*msg];
}

BOOL createTestDir(NSURL *dir)
{
  return [[NSFileManager defaultManager] createDirectoryAtURL:dir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
}

void setup(int iterations, SNTEventLog *eventLog)
{
  // Create and populate necessary values and data structures in advance to
  // minimze the effect on overall run time.
  static const char *commonProcName = "launchd";
  static const char *commonPath = "/sbin/launchd";
  static const char *commonNewPath = "/foo/bar.txt";
  NSArray *execArgs = @[@"/sbin/launchd", @"--init", @"--testing"];

  es_file_t esFile = MakeESFile(commonPath);
  es_process_t esProc = MakeESProcess(&esFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &esProc);

  santa_message_t santaMsg = {0};

  santaMsg.uid = 242;
  santaMsg.gid = 20;
  santaMsg.pid = 1;
  santaMsg.pidversion = 2;
  santaMsg.ppid = 3;

  strlcpy(santaMsg.path, commonPath, sizeof(santaMsg.path));
  strlcpy(santaMsg.newpath, commonNewPath, sizeof(santaMsg.newpath));
  strlcpy(santaMsg.pname, commonProcName, sizeof(santaMsg.pname));

  santaMsg.args_array = (__bridge void*)execArgs;
  santaMsg.es_message = &esMsg;

  for (int i = 0; i < iterations; i++) {
    [eventLog logFileModification:santaMsg];
  }
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    static const struct option longopts[] = {
      {"iter", required_argument, NULL, 'i'},
      {"logger", required_argument, NULL, 'l'},
      {NULL, 0, NULL, 0},
    };

    int ch;
    int iterations = 10;
    Class eventLogClass = [SNTFileEventLog class];
    SNTConfigurator *configurator = [SNTConfigurator configurator];

    while ((ch = getopt_long(argc, argv, "i:l:", longopts, NULL)) != -1) {
      switch (ch) {
        case 'i':
          iterations = atoi(optarg);
          break;
        case 'l':
          if (strcmp(optarg, "syslog") == 0) {
            eventLogClass = [SNTSyslogEventLog class];
          } else if (strcmp(optarg, "file") == 0) {
            eventLogClass = [SNTFileEventLog class];
          } else if (strcmp(optarg, "protobuf") == 0) {
            eventLogClass = [SNTProtobufEventLog class];
          } else {
            usage();
            exit(1);
          }
          break;
        default:
          usage();
          exit(1);
      }
    }

    NSURL *santaTestDir = [NSURL fileURLWithPath:
        [NSTemporaryDirectory() stringByAppendingPathComponent:@"santa_test"]];
    NSURL *tempDir = [santaTestDir URLByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    NSURL *mailDir = [tempDir URLByAppendingPathComponent:@"pblogger"];
    NSURL *fileDir = [tempDir URLByAppendingPathComponent:@"filelogger"];
    NSString *eventLogPath = [[fileDir URLByAppendingPathComponent:@"santa.log"] path];

    [[NSFileManager defaultManager] createDirectoryAtURL:mailDir
        withIntermediateDirectories:YES attributes:nil error:nil];
    [[NSFileManager defaultManager] createDirectoryAtURL:fileDir
        withIntermediateDirectories:YES attributes:nil error:nil];

    configurator.configState[@"EventLogPath"] = eventLogPath;
    configurator.configState[@"EventMailDirectory"] = mailDir.path;

    NSLog(@"Using log path: %@", configurator.eventLogPath);
    NSLog(@"Using mail dir: %@", configurator.eventMailDirectory);
    NSLog(@"Using logger: %@", eventLogClass);

    SNTEventLog *eventLog = [[eventLogClass alloc] init];
    setup(iterations, eventLog);
    [eventLog forceFlush];
  }
}
