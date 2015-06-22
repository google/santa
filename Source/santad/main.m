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

#include "SNTLogging.h"

#include <pthread/pthread.h>
#include <sys/resource.h>

#import "SNTApplication.h"

///  Converts a timeval struct to double, converting the microseconds value to seconds.
static inline double timeval_to_double(struct timeval tv) {
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

///  The watchdog thread function, used to monitor santad CPU/RAM usage and print a warning
///  if it goes over certain thresholds.
void *watchdog_thread_f(__unused void *idata) {
  pthread_setname_np("Watchdog");

  // Number of seconds to wait between checks.
  const int timeInterval = 60;

  // Amount of CPU usage to trigger warning, as a percentage averaged over timeInterval
  // santad's usual CPU usage is 0-3% but can occasionally spike if lots of processes start at once.
  const int cpuWarnThreshold = 20;

  // Amount of RAM usage to trigger warning, in MB.
  // santad's usual RAM usage is between 5-50MB but can spike if lots of processes start at once.
  const int memWarnThreshold = 100;

  struct rusage usage;
  static double prev_total_time = 0.0;
  struct mach_task_basic_info t_info;
  mach_msg_type_number_t t_info_count = MACH_TASK_BASIC_INFO_COUNT;

  while(true) {
    sleep(timeInterval);

    // CPU
    getrusage(RUSAGE_SELF, &usage);
    double total_time = timeval_to_double(usage.ru_utime) + timeval_to_double(usage.ru_stime);
    double percentage = (((total_time - prev_total_time) / (double)timeInterval) * 100.0);
    prev_total_time = total_time;

    if (percentage > cpuWarnThreshold) {
      LOGW(@"Watchdog: potentially high CPU use, ~%.2f%% over last %d seconds.",
           percentage, timeInterval);
    }

    // RAM
    if (KERN_SUCCESS == task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                  (task_info_t)&t_info, &t_info_count)) {
      double ramUseMb = (double) t_info.resident_size / 1024 / 1024;
      if (ramUseMb > (double)memWarnThreshold) {
        LOGW(@"Watchdog: potentially high RAM use, RSS is %.2fMB.", ramUseMb);
      }
    }
  }
  return NULL;
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    // Do not buffer stdout
    setbuf(stdout, NULL);

    NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];

    if ([[[NSProcessInfo processInfo] arguments] containsObject:@"-v"]) {
      printf("%s\n", [infoDict[@"CFBundleVersion"] UTF8String]);
      return 0;
    }

    LOGI(@"Started, version %@", infoDict[@"CFBundleVersion"]);

    SNTApplication *s = [[SNTApplication alloc] init];
    [s performSelectorInBackground:@selector(run) withObject:nil];

    // Create watchdog thread
    pthread_t watchdog_thread;
    pthread_create(&watchdog_thread, NULL, watchdog_thread_f, NULL);

    [[NSRunLoop mainRunLoop] run];
  }
}
