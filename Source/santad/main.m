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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/santad/EventProviders/SNTDriverManager.h"
#import "Source/santad/SNTApplication.h"

#include <mach/task.h>
#include <pthread/pthread.h>
#include <sys/resource.h>

extern uint64_t watchdogCPUEvents;
extern uint64_t watchdogRAMEvents;
extern double watchdogCPUPeak;
extern double watchdogRAMPeak;

///  Converts a timeval struct to double, converting the microseconds value to seconds.
static inline double timeval_to_double(time_value_t tv) {
  return (double)tv.seconds + (double)tv.microseconds / 1000000.0;
}

///  The watchdog thread function, used to monitor santad CPU/RAM usage and print a warning
///  if it goes over certain thresholds.
void *watchdogThreadFunction(__unused void *idata) {
  pthread_setname_np("com.google.santa.watchdog");

  // Number of seconds to wait between checks.
  const int timeInterval = 30;

  // Amount of CPU usage to trigger warning, as a percentage averaged over timeInterval
  // santad's usual CPU usage is 0-3% but can occasionally spike if lots of processes start at once.
  const int cpuWarnThreshold = 20.0;

  // Amount of RAM usage to trigger warning, in MB.
  // santad's usual RAM usage is between 5-50MB but can spike if lots of processes start at once.
  const int memWarnThreshold = 250;

  double prevTotalTime = 0.0;
  double prevRamUseMB = 0.0;
  struct mach_task_basic_info taskInfo;
  mach_msg_type_number_t taskInfoCount = MACH_TASK_BASIC_INFO_COUNT;

  while (true) {
    @autoreleasepool {
      if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                    (task_info_t)&taskInfo, &taskInfoCount) == KERN_SUCCESS) {
        // CPU
        double totalTime = (timeval_to_double(taskInfo.user_time) +
                            timeval_to_double(taskInfo.system_time));
        double percentage = (((totalTime - prevTotalTime) / (double)timeInterval) * 100.0);
        prevTotalTime = totalTime;

        if (percentage > cpuWarnThreshold) {
          LOGW(@"Watchdog: potentially high CPU use, ~%.2f%% over last %d seconds.",
               percentage, timeInterval);
          watchdogCPUEvents++;
        }

        if (percentage > watchdogCPUPeak) watchdogCPUPeak = percentage;

        // RAM
        double ramUseMB = (double)taskInfo.resident_size / 1024 / 1024;
        if (ramUseMB > memWarnThreshold && ramUseMB > prevRamUseMB) {
          LOGW(@"Watchdog: potentially high RAM use, RSS is %.2fMB.", ramUseMB);
          watchdogRAMEvents++;
        }
        prevRamUseMB = ramUseMB;

        if (ramUseMB > watchdogRAMPeak) watchdogRAMPeak = ramUseMB;
      }

      sleep(timeInterval);
    }
  }
  return NULL;
}

void cleanup() {
  LOGI(@"com.google.santa.daemon is running from an unexpected path: cleaning up");
  NSFileManager *fm = [NSFileManager defaultManager];
  [fm removeItemAtPath:@"/Library/LaunchDaemons/com.google.santad.plist" error:NULL];
  [SNTDriverManager unloadDriver];
  [fm removeItemAtPath:@"/Library/Extensions/santa-driver.kext" error:NULL];

  LOGI(@"loading com.google.santa.daemon as a SystemExtension");
  NSTask *t = [[NSTask alloc] init];
  t.launchPath = [@(kSantaAppPath) stringByAppendingString:@"/Contents/MacOS/Santa"];
  t.arguments = @[ @"--load-system-extension" ];
  [t launch];
  [t waitUntilExit];

  t = [[NSTask alloc] init];
  t.launchPath = @"/bin/launchctl";
  t.arguments = @[ @"remove", @"com.google.santad" ];
  [t launch];
  [t waitUntilExit];

  // This exit will likely never be called because the above launchctl command kill us.
  exit(0);
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    // Do not wait on child processes
    signal(SIGCHLD, SIG_IGN);

    NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
    NSProcessInfo *pi = [NSProcessInfo processInfo];

    if ([pi.arguments containsObject:@"-v"]) {
      printf("%s\n", [infoDict[@"CFBundleVersion"] UTF8String]);
      return 0;
    }

    LOGI(@"Started, version %@", infoDict[@"CFBundleVersion"]);

    // Handle the case of macOS < 10.15 updating to >= 10.15.
    if ([[SNTConfigurator configurator] enableSystemExtension]) {
      if ([pi.arguments.firstObject isEqualToString:@(kSantaDPath)]) cleanup();
    }

    SNTApplication *s = [[SNTApplication alloc] init];
    [s start];

    // Create watchdog thread
    pthread_t watchdogThread;
    pthread_create(&watchdogThread, NULL, watchdogThreadFunction, NULL);

    [[NSRunLoop mainRunLoop] run];
  }
}
