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

#import "SNTLogging.h"

#import <asl.h>
#import <pthread.h>

#ifdef DEBUG
static LogLevel logLevel = LOG_LEVEL_DEBUG;
#else
static LogLevel logLevel = LOG_LEVEL_INFO;  // default to info
#endif

void syslogClientDestructor(void *arg) {
  asl_close((aslclient)arg);
}

void logMessage(LogLevel level, FILE *destination, NSString *format, ...) {
  static BOOL useSyslog = NO;
  static const char *binaryName;
  static dispatch_once_t pred;
  static pthread_key_t syslogKey = 0;

  dispatch_once(&pred, ^{
    binaryName = [[[NSProcessInfo processInfo] processName] UTF8String];

    // If debug logging is enabled, the process must be restarted.
    if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--debug"]) {
      logLevel = LOG_LEVEL_DEBUG;
    }

    // If requested, redirect output to syslog.
    if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--syslog"] ||
        strncmp(binaryName, "santad", 6) == 0) {
      useSyslog = YES;
      pthread_key_create(&syslogKey, syslogClientDestructor);
    }
  });

  if (logLevel < level) return;

  va_list args;
  va_start(args, format);
  NSString *s = [[NSString alloc] initWithFormat:format arguments:args];
  va_end(args);

  if (useSyslog) {
    aslclient client = (aslclient)pthread_getspecific(syslogKey);
    if (client == NULL) {
      client = asl_open(NULL, "com.google.santa", 0);
      asl_set_filter(client, ASL_FILTER_MASK_UPTO(ASL_LEVEL_DEBUG));
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
        syslogLevel = ASL_LEVEL_INFO;
        break;
      case LOG_LEVEL_DEBUG:
        levelName = "D";
        syslogLevel = ASL_LEVEL_DEBUG;
        break;
    }

    asl_log(client, NULL, syslogLevel, "%s %s: %s", levelName, binaryName, [s UTF8String]);
  } else {
    fprintf(destination, "%s\n", [s UTF8String]);
  }
}
