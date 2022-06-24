/// Copyright 2022 Google Inc. All rights reserved.
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

#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <mach/task.h>

#import "Source/common/SNTLogging.h"
#import "Source/santad/santad.h"

const int kWatchdogTimeInterval = 10;

extern "C" uint64_t watchdogCPUEvents;
extern "C" uint64_t watchdogRAMEvents;
extern "C" double watchdogCPUPeak;
extern "C" double watchdogRAMPeak;

///  Converts a timeval struct to double, converting the microseconds value to seconds.
static inline double timeval_to_double(time_value_t tv) {
  return (double)tv.seconds + (double)tv.microseconds / 1000000.0;
}

///  The watchdog thread function, used to monitor santad CPU/RAM usage and print a warning
///  if it goes over certain thresholds.
static void SantaWatchdog(__unused void *unused) {
  // Number of seconds to wait between checks.


  // Amount of CPU usage to trigger warning, as a percentage averaged over kWatchdogTimeInterval
  // santad's usual CPU usage is 0-3% but can occasionally spike if lots of processes start at once.
  const int cpuWarnThreshold = 20.0;

  // Amount of RAM usage to trigger warning, in MB.
  // santad's usual RAM usage is between 5-50MB but can spike if lots of processes start at once.
  const int memWarnThreshold = 250;

  double prevTotalTime = 0.0;
  double prevRamUseMB = 0.0;
  struct mach_task_basic_info taskInfo;
  mach_msg_type_number_t taskInfoCount = MACH_TASK_BASIC_INFO_COUNT;

  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&taskInfo,
                &taskInfoCount) == KERN_SUCCESS) {
    // CPU
    double totalTime =
      (timeval_to_double(taskInfo.user_time) + timeval_to_double(taskInfo.system_time));
    double percentage = (((totalTime - prevTotalTime) / (double)kWatchdogTimeInterval) * 100.0);
    prevTotalTime = totalTime;

    if (percentage > cpuWarnThreshold) {
      LOGW(@"Watchdog: potentially high CPU use, ~%.2f%% over last %d seconds.", percentage,
           kWatchdogTimeInterval);
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

    if (ramUseMB > watchdogRAMPeak) {
      watchdogRAMPeak = ramUseMB;
    }
  }
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    // Do not wait on child processes
    signal(SIGCHLD, SIG_IGN);

    NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
    NSProcessInfo *pi = [NSProcessInfo processInfo];

    NSString *productVersion = infoDict[@"CFBundleShortVersionString"];
    NSString *buildVersion =
      [[infoDict[@"CFBundleVersion"] componentsSeparatedByString:@"."] lastObject];

    if ([pi.arguments containsObject:@"-v"]) {
      printf("%s (build %s)\n", [productVersion UTF8String], [buildVersion UTF8String]);
      return 0;
    }

    dispatch_queue_t watchdogQueue = dispatch_queue_create("com.google.santa.daemon.watchdog", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    dispatch_source_t watchdogTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, watchdogQueue);

    if (watchdogTimer) {
      dispatch_source_set_timer(watchdogTimer, DISPATCH_TIME_NOW, kWatchdogTimeInterval * NSEC_PER_SEC, 0);
      dispatch_source_set_event_handler_f(watchdogTimer, SantaWatchdog);
      dispatch_set_context(watchdogTimer, nullptr);
      dispatch_resume(watchdogTimer);
    } else {
      LOGE(@"Failed to start Santa watchdog");
    }

    // auto es_api = std::make_shared<EndpointSecurityAPI>();
    // SantadMain(es_api);
    SantadMain();

    // TODO: Remove `--quick` support used during development

    NSArray *args = [[NSProcessInfo processInfo] arguments];
    if ([args count] > 1 && [args[1] isEqualToString:@"--quick"]) {
      int timeout = 5;
      if ([args count] > 2) {
        timeout = atoi([args[2] UTF8String]);
      }

      LOGI(@"Bailing in %d seconds", timeout);

      dispatch_semaphore_t sema = dispatch_semaphore_create(0);

      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, timeout * NSEC_PER_SEC),
                     dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
                     ^{
        dispatch_semaphore_signal(sema);
      });

      if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (timeout + 2) * NSEC_PER_SEC)) != 0) {
        LOGE(@"Failed to wakeup, bailing...");
        exit(EXIT_FAILURE);
      }
    } else {
      [[NSRunLoop mainRunLoop] run];
    }
  }

  return 0;
}
