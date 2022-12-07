/// Copyright 2015-2022 Google Inc. All rights reserved.
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
#include <memory>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SystemResources.h"
#import "Source/santad/Santad.h"
#include "Source/santad/SantadDeps.h"

using santa::santad::SantadDeps;

// Number of seconds to wait between checks.
const int kWatchdogTimeInterval = 30;

extern "C" uint64_t watchdogCPUEvents;
extern "C" uint64_t watchdogRAMEvents;
extern "C" double watchdogCPUPeak;
extern "C" double watchdogRAMPeak;

struct WatchdogState {
  double prev_total_time;
  double prev_ram_use_mb;
};

///  The watchdog thread function, used to monitor santad CPU/RAM usage and print a warning
///  if it goes over certain thresholds.
static void SantaWatchdog(void *context) {
  WatchdogState *state = (WatchdogState *)context;

  // Amount of CPU usage to trigger warning, as a percentage averaged over kWatchdogTimeInterval
  // santad's usual CPU usage is 0-3% but can occasionally spike if lots of processes start at once.
  const int cpu_warn_threshold = 20.0;

  // Amount of RAM usage to trigger warning, in MB.
  // santad's usual RAM usage is between 5-50MB but can spike if lots of processes start at once.
  const int mem_warn_threshold = 250;

  std::optional<SantaTaskInfo> tinfo = GetTaskInfo();

  if (tinfo.has_value()) {
    // CPU
    double total_time =
      (tinfo->total_user_nanos + tinfo->total_system_nanos) / (double)NSEC_PER_SEC;
    double percentage =
      (((total_time - state->prev_total_time) / (double)kWatchdogTimeInterval) * 100.0);
    state->prev_total_time = total_time;

    if (percentage > cpu_warn_threshold) {
      LOGW(@"Watchdog: potentially high CPU use, ~%.2f%% over last %d seconds.", percentage,
           kWatchdogTimeInterval);
      watchdogCPUEvents++;
    }

    if (percentage > watchdogCPUPeak) watchdogCPUPeak = percentage;

    // RAM
    double ram_use_mb = (double)tinfo->resident_size / 1024 / 1024;
    if (ram_use_mb > mem_warn_threshold && ram_use_mb > state->prev_ram_use_mb) {
      LOGW(@"Watchdog: potentially high RAM use, RSS is %.2fMB.", ram_use_mb);
      watchdogRAMEvents++;
    }
    state->prev_ram_use_mb = ram_use_mb;

    if (ram_use_mb > watchdogRAMPeak) {
      watchdogRAMPeak = ram_use_mb;
    }
  }
}

void CleanupAndReExec() {
  LOGI(@"com.google.santa.daemon is running from an unexpected path: cleaning up");
  NSFileManager *fm = [NSFileManager defaultManager];
  [fm removeItemAtPath:@"/Library/LaunchDaemons/com.google.santad.plist" error:NULL];

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

  // This exit will likely never be called because the above launchctl command will kill us.
  exit(0);
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    // Do not wait on child processes
    signal(SIGCHLD, SIG_IGN);

    NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
    NSProcessInfo *pi = [NSProcessInfo processInfo];

    NSString *product_version = info_dict[@"CFBundleShortVersionString"];
    NSString *build_version =
      [[info_dict[@"CFBundleVersion"] componentsSeparatedByString:@"."] lastObject];

    if ([pi.arguments containsObject:@"-v"]) {
      printf("%s (build %s)\n", [product_version UTF8String], [build_version UTF8String]);
      return 0;
    }

    // Ensure Santa daemon is started as a system extension
    if ([pi.arguments.firstObject isEqualToString:@(kSantaDPath)]) {
      // Does not return
      CleanupAndReExec();
    }

    dispatch_queue_t watchdog_queue = dispatch_queue_create(
      "com.google.santa.daemon.watchdog", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    dispatch_source_t watchdog_timer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, watchdog_queue);

    WatchdogState state = {.prev_total_time = 0.0, .prev_ram_use_mb = 0.0};

    if (watchdog_timer) {
      dispatch_source_set_timer(watchdog_timer, DISPATCH_TIME_NOW,
                                kWatchdogTimeInterval * NSEC_PER_SEC, 0);
      dispatch_source_set_event_handler_f(watchdog_timer, SantaWatchdog);
      dispatch_set_context(watchdog_timer, &state);
      dispatch_resume(watchdog_timer);
    } else {
      LOGE(@"Failed to start Santa watchdog");
    }

    std::unique_ptr<SantadDeps> deps =
      SantadDeps::Create([SNTConfigurator configurator], [SNTMetricSet sharedInstance]);

    // This doesn't return
    SantadMain(deps->ESAPI(), deps->Logger(), deps->Metrics(), deps->WatchItems(), deps->Enricher(),
               deps->AuthResultCache(), deps->ControlConnection(), deps->CompilerController(),
               deps->NotifierQueue(), deps->SyncdQueue(), deps->ExecController(),
               deps->PrefixTree());
  }

  return 0;
}
