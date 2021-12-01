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
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/Commands/SNTCommandMetrics.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@implementation SNTCommandMetrics

REGISTER_COMMAND_NAME(@"metrics")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Show Santa metric information.";
}

+ (NSString *)longHelpText {
  return (@"Provides metrics about Santa's operation while it's running.\n"
          @"  Use --json to output in JSON format");
}

- (NSString *)stringFromMetricFormat:(SNTMetricFormatType)format {
  switch (format) {
    case SNTMetricFormatTypeMonarchJSON: return @"monarchjson";
    case SNTMetricFormatTypeRawJSON: return @"rawjson";
    default: return @"Unknown Metric Format";
  }
}

- (NSDictionary *)normalize:(NSDictionary *)metrics {
  NSMutableDictionary *mutableMetrics = [metrics mutableCopy];

  id formatter;

  if (@available(macOS 10.13, *)) {
    NSISO8601DateFormatter *isoFormatter = [[NSISO8601DateFormatter alloc] init];

    isoFormatter.formatOptions =
      NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
    formatter = isoFormatter;
  } else {
    NSDateFormatter *localFormatter = [[NSDateFormatter alloc] init];
    [localFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"];
    [localFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
    formatter = localFormatter;
  }

  for (NSString *metricName in mutableMetrics[@"metrics"]) {
    NSMutableDictionary *metric = mutableMetrics[@"metrics"][metricName];

    for (NSString *field in metric[@"fields"]) {
      NSMutableArray<NSMutableDictionary *> *values = metric[@"fields"][field];

      [values enumerateObjectsUsingBlock:^(id object, NSUInteger index, BOOL *stop) {
        values[index][@"created"] = [formatter stringFromDate:values[index][@"created"]];
        values[index][@"last_updated"] = [formatter stringFromDate:values[index][@"last_updated"]];
      }];
    }
  }

  return mutableMetrics;
}

- (void)prettyPrintRootLabels:(NSDictionary *)rootLabels {
  for (NSString *label in rootLabels) {
    const char *labelStr = [label cStringUsingEncoding:NSUTF8StringEncoding];
    const char *valueStr = [rootLabels[label] cStringUsingEncoding:NSUTF8StringEncoding];

    printf("  %-25s | %s\n", labelStr, valueStr);
  }
}

- (void)prettyPrintMetricValues:(NSDictionary *)metrics {
  for (NSString *metricName in metrics) {
    NSDictionary *metric = metrics[metricName];
    const char *metricNameStr = [metricName UTF8String];
    const char *description = [metric[@"description"] UTF8String];
    NSString *metricType = SNTMetricMakeStringFromMetricType([metric[@"type"] integerValue]);
    const char *metricTypeStr = [metricType UTF8String];

    printf("  %-25s | %s\n", "Metric Name", metricNameStr);
    printf("  %-25s | %s\n", "Description", description);
    printf("  %-25s | %s\n", "Type", metricTypeStr);

    for (NSString *fieldName in metric[@"fields"]) {
      for (NSDictionary *field in metric[@"fields"][fieldName]) {
        const char *fieldNameStr = [fieldName cStringUsingEncoding:NSUTF8StringEncoding];
        const char *fieldValueStr = [field[@"value"] cStringUsingEncoding:NSUTF8StringEncoding];
        const char *createdStr = [field[@"created"] UTF8String];
        const char *lastUpdatedStr = [field[@"last_updated"] UTF8String];
        const char *data = [[NSString stringWithFormat:@"%@", field[@"data"]] UTF8String];

        if (strlen(fieldNameStr) > 0) {
          printf("  %-25s | %s=%s\n", "Field", fieldNameStr, fieldValueStr);
        }

        printf("  %-25s | %s\n", "Created", createdStr);
        printf("  %-25s | %s\n", "Last Updated", lastUpdatedStr);
        printf("  %-25s | %s\n", "Data", data);
      }
    }
    printf("\n");
  }
}

- (void)prettyPrintMetrics:(NSDictionary *)metrics asJSON:(BOOL)exportJSON {
  BOOL exportMetrics = [[SNTConfigurator configurator] exportMetrics];
  NSURL *metricsURLStr = [[SNTConfigurator configurator] metricURL];
  SNTMetricFormatType metricFormat = [[SNTConfigurator configurator] metricFormat];
  NSUInteger metricExportInterval = [[SNTConfigurator configurator] metricExportInterval];
  NSDictionary *normalizedMetrics = [self normalize:metrics];

  if (exportJSON) {
    // Format
    NSData *metricData = [NSJSONSerialization dataWithJSONObject:normalizedMetrics
                                                         options:NSJSONWritingPrettyPrinted
                                                           error:nil];
    NSString *metricStr = [[NSString alloc] initWithData:metricData encoding:NSUTF8StringEncoding];
    printf("%s\n", [metricStr UTF8String]);
    return;
  }

  if (!exportMetrics) {
    printf("Metrics not configured\n");
    return;
  }

  printf(">>> Metrics Info\n");
  printf("  %-25s | %s\n", "Metrics Server", [metricsURLStr.absoluteString UTF8String]);
  printf("  %-25s | %s\n", "Metrics Format",
         [[self stringFromMetricFormat:metricFormat] UTF8String]);
  printf("  %-25s | %lu\n", "Export Interval (seconds)", metricExportInterval);
  printf("\n");

  printf(">>> Root Labels\n");
  [self prettyPrintRootLabels:normalizedMetrics[@"root_labels"]];
  printf("\n");
  printf(">>> Metrics \n");
  [self prettyPrintMetricValues:normalizedMetrics[@"metrics"]];
}

- (void)runWithArguments:(NSArray *)arguments {
  __block NSDictionary *metrics;

  dispatch_group_t group = dispatch_group_create();
  dispatch_group_enter(group);

  [[self.daemonConn remoteObjectProxy] metrics:^(NSDictionary *exportedMetrics) {
    metrics = exportedMetrics;
    dispatch_group_leave(group);
  }];

  // Wait a maximum of 5s for metrics collected from daemon to arrive.
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 5))) {
    fprintf(stderr, "Failed to retrieve metrics from daemon\n\n");
  }

  [self prettyPrintMetrics:metrics asJSON:[arguments containsObject:@"--json"]];
  exit(0);
}

@end
