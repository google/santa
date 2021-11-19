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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTSystemInfo.h"

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/resource.h>

/**
 * Register the mode metric checking the config before reporting the status.
 */
static void RegisterModeMetric(SNTMetricSet *metricSet) {
  SNTMetricStringGauge *mode = [metricSet stringGaugeWithName:@"/santa/mode"
                                                   fieldNames:@[]
                                                     helpText:@"Santa's operating mode"];

  // create a callback that gets the current mode
  [metricSet registerCallback:^{
    SNTConfigurator *config = [SNTConfigurator configurator];

    switch (config.clientMode) {
      case SNTClientModeLockdown: [mode set:@"lockdown" forFieldValues:@[]]; break;
      case SNTClientModeMonitor: [mode set:@"monitor" forFieldValues:@[]]; break;
      default:
        // Should never be reached.
        [mode set:@"unknown" forFieldValues:@[]];
        break;
    }
  }];
}

/**
 * Register metrics for measuring memory usage.
 */
static void RegisterMemoryAndCPUMetrics(SNTMetricSet *metricSet) {
  SNTMetricInt64Gauge *vsize =
    [metricSet int64GaugeWithName:@"/proc/memory/virtual_size"
                       fieldNames:@[]
                         helpText:@"The virtual memory size of this process"];
  SNTMetricInt64Gauge *rsize =
    [metricSet int64GaugeWithName:@"/proc/memory/resident_size"
                       fieldNames:@[]
                         helpText:@"The resident set size of this process"];

  SNTMetricDoubleGauge *cpuUsage =
    [metricSet doubleGaugeWithName:@"/proc/cpu_usage"
                        fieldNames:@[ @"mode" ]  // "user" or "system"
                          helpText:@"CPU time consumed by this process, in seconds"];

  [metricSet registerCallback:^(void) {
    struct mach_task_basic_info info;
    mach_msg_type_number_t size = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t ret =
      task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &size);

    if (ret != KERN_SUCCESS) {
      return;
    }

    [vsize set:info.virtual_size forFieldValues:@[]];
    [rsize set:info.resident_size forFieldValues:@[]];

    // convert times to seconds
    double user_time = info.user_time.seconds + (info.user_time.microseconds / 1e6);
    double system_time = info.system_time.seconds + (info.system_time.microseconds / 1e6);

    [cpuUsage set:user_time forFieldValues:@[ @"user" ]];
    [cpuUsage set:system_time forFieldValues:@[ @"system" ]];
  }];
}

static void RegisterHostnameAndUsernameLabels(SNTMetricSet *metricSet) {
  NSString *hostname = [NSProcessInfo processInfo].hostName;

  [metricSet addRootLabel:@"host_name" value:hostname];
  [metricSet addRootLabel:@"username" value:NSUserName()];
  [metricSet addRootLabel:@"job_name" value:@"santad"];
  [metricSet addRootLabel:@"service_name" value:@"santa"];

  // get extra root labels from configuration
  SNTConfigurator *config = [SNTConfigurator configurator];

  NSDictionary *extraLabels = [config extraMetricLabels];

  if (extraLabels == nil) {
    return;
  }

  if ([extraLabels count] >= 0) {
    for (NSString *key in extraLabels) {
      // remove the root label if the value is empty.
      if ([@"" isEqualToString:(NSString *)extraLabels[key]]) {
        [metricSet removeRootLabel:key];
        continue;
      }

      // Set or override the value.
      [metricSet addRootLabel:key value:(NSString *)extraLabels[key]];
    }
  }
}

static void RegisterCommonSantaMetrics(SNTMetricSet *metricSet) {
  NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];

  // register the version
  [metricSet addConstantStringWithName:@"/build/label"
                              helpText:@"Version of the binary"
                                 value:version];

  // register start time
  [metricSet
    addConstantIntegerWithName:@"/proc/birth_timestamp"
                      helpText:@"Start time of Santad, in microseconds since epoch"
                         value:(long long)([[NSDate date] timeIntervalSince1970] * 1000000)];

  // Register OS version
  [metricSet addConstantStringWithName:@"/proc/os/version"
                              helpText:@"Short operating System version"
                                 value:[SNTSystemInfo osVersion]];

  RegisterModeMetric(metricSet);
  // TODO(markowsky) Register CSR status
  // TODO(markowsky) Register system extension status
}

void SNTRegisterCoreMetrics() {
  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
  RegisterHostnameAndUsernameLabels(metricSet);
  RegisterMemoryAndCPUMetrics(metricSet);
  RegisterCommonSantaMetrics(metricSet);
}
