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

#import <Foundation/Foundation.h>

#import "Source/common/SNTMetricSet.h"
#import "Source/santametricservice/Formats/SNTMetricFormatTestHelper.h"

@implementation SNTMetricFormatTestHelper
+ (NSDictionary *)convertDatesToFixedDateWithExportDict:(NSMutableDictionary *)exportDict {
  NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
  [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"];
  NSDate *fixedDate = [formatter dateFromString:@"2021-09-16T21:07:34.826Z"];

  for (NSString *metricName in exportDict[@"metrics"]) {
    NSMutableDictionary *metric = exportDict[@"metrics"][metricName];

    for (NSString *field in metric[@"fields"]) {
      NSMutableArray<NSMutableDictionary *> *values = metric[@"fields"][field];

      [values enumerateObjectsUsingBlock:^(id object, NSUInteger index, BOOL *stop) {
        values[index][@"created"] = fixedDate;
        values[index][@"last_updated"] = fixedDate;
      }];
    }
  }

  return exportDict;
}

+ (NSDictionary *)createValidMetricsDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] initWithHostname:@"testHost"
                                                          username:@"testUser"];

  // Add constants
  [metricSet addConstantStringWithName:@"/build/label"
                              helpText:@"Software version running"
                                 value:@"20210809.0.1"];
  [metricSet addConstantBooleanWithName:@"/santa/using_endpoint_security_framework"
                               helpText:@"Is santad using the endpoint security framework"
                                  value:YES];
  [metricSet addConstantIntegerWithName:@"/proc/birth_timestamp"
                               helpText:@"Start time of this santad instance, in microseconds since epoch"
                                  value:(long long)(0x12345668910)];
  // Add Metrics
  SNTMetricCounter *c = [metricSet counterWithName:@"/santa/events"
                                        fieldNames:@[ @"rule_type" ]
                                          helpText:@"Count of process exec events on the host"];

  [c incrementForFieldValues:@[ @"binary" ]];
  [c incrementBy:2 forFieldValues:@[ @"certificate" ]];

  SNTMetricInt64Gauge *g = [metricSet int64GaugeWithName:@"/santa/rules"
                                              fieldNames:@[ @"rule_type" ]
                                                helpText:@"Number of rules"];

  [g set:1 forFieldValues:@[ @"binary" ]];
  [g set:3 forFieldValues:@[ @"certificate" ]];

  // Add Metrics with callback
  SNTMetricInt64Gauge *virtualMemoryGauge =
    [metricSet int64GaugeWithName:@"/proc/memory/virtual_size"
                       fieldNames:@[]
                         helpText:@"The virtual memory size of this process"];

  SNTMetricInt64Gauge *residentMemoryGauge =
    [metricSet int64GaugeWithName:@"/proc/memory/resident_size"
                       fieldNames:@[]
                         helpText:@"The resident set size of this process"];

  [metricSet registerCallback:^(void) {
    [virtualMemoryGauge set:987654321 forFieldValues:@[]];
    [residentMemoryGauge set:123456789 forFieldValues:@[]];
  }];

  NSMutableDictionary *exportDict = [[metricSet export] mutableCopy];

  return [SNTMetricFormatTestHelper convertDatesToFixedDateWithExportDict:exportDict];
}
@end
