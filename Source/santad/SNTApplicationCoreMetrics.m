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
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTConfigurator.h"

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
        
        switch (config.clientMode)  {
            case SNTClientModeLockdown:
                [mode set:@"lockdown" forFieldValues:@[]];
                break;
            case SNTClientModeMonitor:
                [mode set:@"monitor" forFieldValues:@[]];
                break;
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
static void RegisterMemoryMetrics(SNTMetricSet *metricSet) {
  SNTMetricInt64Gauge *vsize = [metricSet int64GaugeWithName:@"/proc/memory/virtual_size"
                                       fieldNames:@[]
                                         helpText:@"The virtual memory size of this process"];
  SNTMetricInt64Gauge *rsize = [metricSet int64GaugeWithName:@"/proc/memory/resident_size"
                                       fieldNames:@[]
                                         helpText:@"The resident set size of this process"];
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
  }];
}

static double RusageTimeToSeconds(struct timeval *rusageTime) {
  return (double)rusageTime->tv_usec * 1.0e-6 + (double)rusageTime->tv_sec;
}

static void RegisterCPUMetrics(SNTMetricSet *metricSet) {
  SNTMetricDoubleGauge *cpuUsage =
      [metricSet doubleGaugeWithName:@"/proc/cpu_usage"
                     fieldNames:@[ @"mode" ]  // "user" or "system"
                       helpText:@"CPU time consumed by this process, in seconds"];

  [metricSet registerCallback:^(void) {
    struct rusage r;
    if (getrusage(RUSAGE_SELF, &r) != 0) {
      return;
    }

    [cpuUsage set:RusageTimeToSeconds(&r.ru_utime) forFieldValues:@[ @"user" ]];
    [cpuUsage set:RusageTimeToSeconds(&r.ru_stime) forFieldValues:@[ @"system" ]];
  }];
}

static void RegisterHostnameAndUsernameLabels(SNTMetricSet *metricSet) {
    [metricSet addRootLabel:@"hostname" value:[NSProcessInfo processInfo].hostName];
    [metricSet addRootLabel:@"username" value:NSUserName()];
    [metricSet addRootLabel:@"job_name" value:@"santad"];
}

static void RegisterCommonSantaMetrics(SNTMetricSet *metricSet) {
    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
    
    // register the version
    [metricSet addConstantStringWithName:@"/build/label"
                                helpText:@"Version of the binary"
                                   value:version];
    
    // register start time
    [metricSet addConstantIntegerWithName:@"/proc/birth_timestamp"
                                 helpText:@"Start time of Santad, in microseconds since epoch"
                                 value:(long long)([[NSDate date] timeIntervalSince1970] * 1000000)];
    
    // Register OS version
    NSProcessInfo *processInfo = [NSProcessInfo processInfo];
    NSString *shortOSVersion = [NSString stringWithFormat:@"%ld.%ld.%ld", processInfo.operatingSystemVersion.majorVersion,
        processInfo.operatingSystemVersion.minorVersion,
        processInfo.operatingSystemVersion.patchVersion];

    [metricSet addConstantStringWithName:@"/proc/os/version"
                                helpText:@"Short operating System version"
                                   value:shortOSVersion];
    
    RegisterModeMetric(metricSet);
    // TODO(markowsky) Register CSR status
    // TODO(markowsky) Register system extension status
    
}


void SNTRegisterCoreMetrics() {
    SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
    RegisterHostnameAndUsernameLabels(metricSet);
    RegisterMemoryMetrics(metricSet);
    RegisterCPUMetrics(metricSet);
    RegisterCommonSantaMetrics(metricSet);
}

