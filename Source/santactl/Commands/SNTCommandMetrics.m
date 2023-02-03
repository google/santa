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
          @"Pass prefixes to filter list of metrics, if desired.\n"
          @"  Use --json to output in JSON format");
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
        const char *createdStr = [field[@"created"] UTF8String];
        const char *lastUpdatedStr = [field[@"last_updated"] UTF8String];
        const char *data = [[NSString stringWithFormat:@"%@", field[@"data"]] UTF8String];

        NSArray<NSString *> *fields = [fieldName componentsSeparatedByString:@","];
        NSArray<NSString *> *fieldValues = [field[@"value"] componentsSeparatedByString:@","];

        if (fields.count != fieldValues.count) {
          fprintf(stderr, "metric %s has a different number of field names and field values",
                  [fieldName UTF8String]);
          continue;
        }

        NSString *fieldDisplayString = @"";

        if (fields.count >= 1 && fields[0].length) {
          for (int i = 0; i < fields.count; i++) {
            fieldDisplayString = [fieldDisplayString
              stringByAppendingString:[NSString
                                        stringWithFormat:@"%@=%@", fields[i], fieldValues[i]]];
            if (i < fields.count - 1) {
              fieldDisplayString = [fieldDisplayString stringByAppendingString:@","];
            }
          }
        }

        if (![fieldDisplayString isEqualToString:@""]) {
          printf("  %-25s | %s\n", "Field", [fieldDisplayString UTF8String]);
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
  NSDictionary *normalizedMetrics = SNTMetricConvertDatesToISO8601Strings(metrics);

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
         [SNTMetricStringFromMetricFormatType(metricFormat) UTF8String]);
  printf("  %-25s | %lu\n", "Export Interval (seconds)", metricExportInterval);
  printf("\n");

  printf(">>> Root Labels\n");
  [self prettyPrintRootLabels:normalizedMetrics[@"root_labels"]];
  printf("\n");
  printf(">>> Metrics\n");
  [self prettyPrintMetricValues:normalizedMetrics[@"metrics"]];
}

- (NSDictionary *)filterMetrics:(NSDictionary *)metrics withArguments:(NSArray *)args {
  NSMutableDictionary *outer = [metrics mutableCopy];
  NSMutableDictionary *inner = [NSMutableDictionary dictionary];
  __block BOOL hadFilter = NO;

  [metrics[@"metrics"] enumerateKeysAndObjectsUsingBlock:^(NSString *key, id value, BOOL *stop) {
    for (NSString *arg in args) {
      if ([arg hasPrefix:@"-"]) continue;

      hadFilter = YES;
      if ([key hasPrefix:arg]) {
        inner[key] = value;
      }
    }
  }];

  outer[@"metrics"] = inner;
  return hadFilter ? outer : metrics;
}

- (void)runWithArguments:(NSArray *)arguments {
  __block NSDictionary *metrics;

  [[self.daemonConn synchronousRemoteObjectProxy] metrics:^(NSDictionary *exportedMetrics) {
    metrics = exportedMetrics;
  }];

  metrics = [self filterMetrics:metrics withArguments:arguments];

  [self prettyPrintMetrics:metrics asJSON:[arguments containsObject:@"--json"]];
  exit(0);
}

@end
