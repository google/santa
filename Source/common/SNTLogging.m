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

#import "Source/common/SNTLogging.h"

#import <asl.h>
#import <pthread.h>

#ifdef DEBUG
static LogLevel logLevel = LOG_LEVEL_DEBUG;
#else
static LogLevel logLevel = LOG_LEVEL_INFO;  // default to info
#endif

void syslogClientDestructor(void *arg) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  asl_close((aslclient)arg);
#pragma clang diagnostic pop
}

void logMessage(LogLevel level, FILE *destination, NSString *format, ...) {
  static BOOL useSyslog = NO;
  static NSString *binaryName;
  static dispatch_once_t pred;
  static pthread_key_t syslogKey = 0;

  dispatch_once(&pred, ^{
    binaryName = [[NSProcessInfo processInfo] processName];

    if (@available(macOS 10.15, *)) {
      if ([binaryName isEqualToString:@"santad"]) {
        useSyslog = YES;
        pthread_key_create(&syslogKey, syslogClientDestructor);
      }
    }

    // If debug logging is enabled, the process must be restarted.
    if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--debug"]) {
      logLevel = LOG_LEVEL_DEBUG;
    }

    // If requested, redirect output to syslog.
    if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--syslog"]) {
      useSyslog = YES;
      pthread_key_create(&syslogKey, syslogClientDestructor);
    }
  });

  if (logLevel < level) return;

  va_list args;
  va_start(args, format);
  NSMutableString *s = [[NSMutableString alloc] initWithFormat:format arguments:args];
  va_end(args);

  if (useSyslog) {
    aslclient client = (aslclient)pthread_getspecific(syslogKey);
    if (client == NULL) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      client = asl_open(NULL, "com.google.santa", 0);
      asl_set_filter(client, ASL_FILTER_MASK_UPTO(ASL_LEVEL_DEBUG));
#pragma clang diagnostic pop
      pthread_setspecific(syslogKey, client);
    }

    char *levelName;
    int syslogLevel = ASL_LEVEL_DEBUG;
    switch (level) {
      case LOG_LEVEL_ERROR:
        levelName = "E";
        syslogLevel = ASL_LEVEL_ERR;
        break;
      case LOG_LEVEL_WARN:
        levelName = "W";
        syslogLevel = ASL_LEVEL_WARNING;
        break;
      case LOG_LEVEL_INFO:
        levelName = "I";
        syslogLevel = ASL_LEVEL_NOTICE; // Maps to ULS Default
        break;
      case LOG_LEVEL_DEBUG:
        levelName = "D";
        syslogLevel = ASL_LEVEL_DEBUG;
        break;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    asl_log(client, NULL, syslogLevel, "%s %s: %s", levelName, binaryName.UTF8String, s.UTF8String);
#pragma clang diagnostic pop
  } else {
    [s appendString:@"\n"];
    size_t len = [s lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    fwrite([s UTF8String], len, 1, destination);
  }
}
