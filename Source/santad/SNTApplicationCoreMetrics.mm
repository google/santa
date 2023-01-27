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

#import "Source/santad/SNTApplicationCoreMetrics.h"

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/resource.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SystemResources.h"

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
 * Register the event log type metric checking the config before reporting the status.
 */
static void RegisterEventLogType(SNTMetricSet *metricSet) {
  SNTMetricStringGauge *logType = [metricSet stringGaugeWithName:@"/santa/log_type"
                                                      fieldNames:@[]
                                                        helpText:@"Santa's log type"];

  // create a callback that gets the current log type
  [metricSet registerCallback:^{
    switch ([[SNTConfigurator configurator] eventLogType]) {
      case SNTEventLogTypeProtobuf: [logType set:@"protobuf" forFieldValues:@[]]; break;
      case SNTEventLogTypeSyslog: [logType set:@"syslog" forFieldValues:@[]]; break;
      case SNTEventLogTypeNull: [logType set:@"null" forFieldValues:@[]]; break;
      case SNTEventLogTypeFilelog: [logType set:@"file" forFieldValues:@[]]; break;
      default:
        // Should never be reached.
        [logType set:@"unknown" forFieldValues:@[]];
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
    std::optional<SantaTaskInfo> tinfo = GetTaskInfo();
    if (!tinfo.has_value()) {
      return;
    }

    [vsize set:tinfo->virtual_size forFieldValues:@[]];
    [rsize set:tinfo->resident_size forFieldValues:@[]];

    // convert times to seconds
    double user_time = tinfo->total_user_nanos / (double)NSEC_PER_SEC;
    double system_time = tinfo->total_system_nanos / (double)NSEC_PER_SEC;

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

  if (extraLabels.count == 0) return;

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
  RegisterEventLogType(metricSet);
  // TODO(markowsky) Register CSR status
  // TODO(markowsky) Register system extension status
}

void SNTRegisterCoreMetrics() {
  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
  RegisterHostnameAndUsernameLabels(metricSet);
  RegisterMemoryAndCPUMetrics(metricSet);
  RegisterCommonSantaMetrics(metricSet);
}
