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
#import "Source/santad/SNTApplicationCoreMetrics.h"
#import "Source/santametricservice/Formats/SNTMetricFormatTestHelper.h"

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

@interface SNTApplicationCoreMetricsTest : XCTestCase
@property id mockConfigurator;
@property NSDictionary *extraMetricLabels;
@end

@implementation SNTApplicationCoreMetricsTest

- (void)setUp {
  self.extraMetricLabels = @{@"service_name" : @"santa", @"corp_site" : @"roam"};
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);

  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
}

- (NSDictionary *)fixUpDatesAndDataValuesOf:(NSDictionary *)exportedMetrics {
  NSMutableDictionary *mutableMetrics =
    [[SNTMetricFormatTestHelper convertDatesToFixedDateWithExportDict:exportedMetrics] mutableCopy];

  // Ensure that we got data of the correct type but do not check the values as they'll change per
  // call. Instead we stub out the values for testing.
  NSMutableDictionary *metric = mutableMetrics[@"metrics"][@"/proc/birth_timestamp"];
  XCTAssertTrue([metric[@"fields"][@""][0][@"data"] isKindOfClass:[NSNumber class]],
                @"/proc/birth_timestamp data is not a number");
  metric[@"fields"][@""][0][@"data"] = @1634148013203157;
  mutableMetrics[@"metrics"][@"/proc/birth_timestamp"] = metric;

  // Fix up CPU usage
  metric = mutableMetrics[@"metrics"][@"/proc/cpu_usage"];
  XCTAssertTrue(CFNumberIsFloatType((__bridge CFNumberRef)metric[@"fields"][@"mode"][0][@"data"]),
                @"/proc/cpu_usage has non-floating point data");
  metric[@"fields"][@"mode"][0][@"data"] = @0.63002;
  XCTAssertTrue(CFNumberIsFloatType((__bridge CFNumberRef)metric[@"fields"][@"mode"][1][@"data"]),
                @"/proc/cpu_usage has non-floating point data");
  metric[@"fields"][@"mode"][1][@"data"] = @0.29522;
  metric = mutableMetrics[@"metrics"][@"/proc/cpu_usage"];

  // Fix up Memory (resident size)
  metric = mutableMetrics[@"metrics"][@"/proc/memory/resident_size"];
  XCTAssertFalse(CFNumberIsFloatType((__bridge CFNumberRef)metric[@"fields"][@""][0][@"data"]));
  metric[@"fields"][@""][0][@"data"] = @22097920;
  mutableMetrics[@"metrics"][@"/proc/memory/resident_size"] = metric;

  // Fix up Memory (virtual size)
  metric = mutableMetrics[@"metrics"][@"/proc/memory/virtual_size"];
  XCTAssertFalse(CFNumberIsFloatType((__bridge CFNumberRef)metric[@"fields"][@""][0][@"data"]));
  metric[@"fields"][@""][0][@"data"] = @35634683904;
  mutableMetrics[@"metrics"][@"/proc/memory/virtual_size"] = metric;

  return mutableMetrics;
}

- (void)testRegisteringCoreMetrics {
  OCMStub([self.mockConfigurator extraMetricLabels]).andReturn(self.extraMetricLabels);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator eventLogType]).andReturn(SNTEventLogTypeProtobuf);

  SNTRegisterCoreMetrics();

  NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];

  NSString *shortOSVersion = [SNTSystemInfo osVersion];

  NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
  formatter.formatOptions =
    NSISO8601DateFormatWithFractionalSeconds | NSISO8601DateFormatWithInternetDateTime;

  NSDate *fixedDate = [formatter dateFromString:@"2021-09-16T21:07:34.826Z"];
  NSString *hostname = [NSProcessInfo processInfo].hostName;

  NSDictionary *expected = @{
    @"metrics" : @{
      @"/build/label" : @{
        @"description" : @"Version of the binary",
        @"type" : @2,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : version,
            @"last_updated" : fixedDate,
            @"value" : @""
          } ]
        },
      },
      @"/proc/birth_timestamp" : @{
        @"description" : @"Start time of Santad, in microseconds since epoch",
        @"type" : @3,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : @1634148013203157,
            @"last_updated" : fixedDate,
            @"value" : @""
          } ],
        },
      },
      @"/proc/cpu_usage" : @{
        @"description" : @"CPU time consumed by this process, in seconds",
        @"type" : @8,
        @"fields" : @{
          @"mode" : @[
            @{
              @"created" : fixedDate,
              @"data" : @0.63002,
              @"last_updated" : fixedDate,
              @"value" : @"user"
            },
            @{
              @"created" : fixedDate,
              @"data" : @0.29522,
              @"last_updated" : fixedDate,
              @"value" : @"system"
            }
          ],
        },
      },
      @"/proc/memory/resident_size" : @{
        @"description" : @"The resident set size of this process",
        @"type" : @7,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : @22097920,
            @"last_updated" : fixedDate,
            @"value" : @""
          } ],
        },
      },
      @"/proc/memory/virtual_size" : @{
        @"description" : @"The virtual memory size of this process",
        @"type" : @7,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : @35634683904,
            @"last_updated" : fixedDate,
            @"value" : @""
          } ],
        },
      },
      @"/proc/os/version" : @{
        @"description" : @"Short operating System version",
        @"type" : @2,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : shortOSVersion,
            @"last_updated" : fixedDate,
            @"value" : @""
          } ],
        },
      },
      @"/santa/mode" : @{
        @"description" : @"Santa's operating mode",
        @"type" : @6,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : @"lockdown",
            @"last_updated" : fixedDate,
            @"value" : @""
          } ],
        },
      },
      @"/santa/log_type" : @{
        @"description" : @"Santa's log type",
        @"type" : @6,
        @"fields" : @{
          @"" : @[ @{
            @"created" : fixedDate,
            @"data" : @"protobuf",
            @"last_updated" : fixedDate,
            @"value" : @""
          } ],
        },
      },
    },
    @"root_labels" : @{
      @"host_name" : hostname,
      @"job_name" : @"santad",
      @"service_name" : @"santa",
      @"corp_site" : @"roam",
      @"username" : [NSProcessInfo processInfo].userName
    },
  };

  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];

  NSDictionary *exportedMetrics = [self fixUpDatesAndDataValuesOf:[metricSet export]];
  XCTAssertNotNil(exportedMetrics);

  XCTAssertEqualObjects(expected[@"root_labels"], exportedMetrics[@"root_labels"],
                        @"root_labels are different");

  for (NSString *metricName in expected[@"metrics"]) {
    NSDictionary *other = exportedMetrics[@"metrics"][metricName];
    XCTAssertNotNil(other, @"exported Metrics Missing %@", metricName);
    XCTAssertEqualObjects(expected[@"metrics"][metricName], other,
                          @"%@ does not match expected values", metricName);
  }
}

// Test that setting a new value for an existing rootLabel overwrites the labels value.
//
// Becareful modifiying this test as the singleton makes this order dependent.
//
- (void)testRootLabelReplacement {
  self.extraMetricLabels = @{@"host_name" : @"santa-host"};
  OCMStub([self.mockConfigurator extraMetricLabels]).andReturn(self.extraMetricLabels);

  SNTRegisterCoreMetrics();

  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
  NSDictionary *output = [metricSet export];

  NSDictionary *expectedRootLabels = @{
    @"host_name" : @"santa-host",
    @"job_name" : @"santad",
    @"service_name" : @"santa",
    @"corp_site" : @"roam",
    @"username" : [NSProcessInfo processInfo].userName
  };

  XCTAssertEqualObjects(expectedRootLabels, output[@"root_labels"],
                        @"failed to update host_name root label");
}

// Test that setting a rootLabel key to "" removes it from the root labels.
//
// Becareful modifiying this test as the singleton makes this order dependent.
//
- (void)testRootLabelRemoval {
  self.extraMetricLabels = @{@"host_name" : @""};
  OCMStub([self.mockConfigurator extraMetricLabels]).andReturn(self.extraMetricLabels);

  SNTRegisterCoreMetrics();

  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
  NSDictionary *output = [metricSet export];

  NSDictionary *expectedRootLabels = @{
    @"job_name" : @"santad",
    @"service_name" : @"santa",
    @"corp_site" : @"roam",
    @"username" : [NSProcessInfo processInfo].userName,
  };

  XCTAssertEqualObjects(expectedRootLabels, output[@"root_labels"],
                        @"failed to remove only host_name root label");
}

@end
