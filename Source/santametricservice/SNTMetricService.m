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

#include <dispatch/dispatch.h>
#include <fcntl.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"

#import "SNTMetricService.h"
#import "Source/santametricservice/Formats/SNTMetricRawJSONFormat.h"
#import "Source/santametricservice/Writers/SNTMetricFileWriter.h"

@interface SNTMetricService ()
@property MOLXPCConnection *notifierConnection;
@property MOLXPCConnection *listener;
@property(nonatomic) dispatch_queue_t queue;
@end

@implementation SNTMetricService {
 @private
  SNTMetricRawJSONFormat *rawJSONFormatter;
  NSDictionary *metricWriters;
}

- (instancetype)init {
  self = [super init];

  rawJSONFormatter = [[SNTMetricRawJSONFormat alloc] init];
  metricWriters = @{@"file" : [[SNTMetricFileWriter alloc] init]};

  _queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
  return self;
}

/**
 * Helper function to format NSError's for logging error messages.
 */
- (NSString *)messageFromError:(NSError *)error {
  NSString *message = [error localizedDescription];
  NSString *details = [error localizedFailureReason] ? [error localizedFailureReason] : @"";

  return [NSString stringWithFormat:@"%@ %@", message, details];
}

/**
 * Converts the exported Metrics dicitionary to the appropriate monitoring
 * format.
 *
 *  @param metrics NSDictionary containing the exported metrics
 *  @param format SNTMetricFormatType the exported metrics format
 *  @return An array of metrics formatted according to the specified format or
 *          nil on error;
 */
- (NSArray<NSData *> *)convertMetrics:(NSDictionary *)metrics
                             toFormat:(SNTMetricFormatType)format
                                error:(NSError **)err {
  switch (format) {
    case SNTMetricFormatTypeRawJSON: return [self->rawJSONFormatter convert:metrics error:err];
    default: return nil;
  }
}

/**
 * Exports the metrics for a configured monitoring system, if santa is
 * configured to do so.
 *
 * @param metrics The NSDictionary from a MetricSet export call.
 */
- (void)exportForMonitoring:(NSDictionary *)metrics {
  SNTConfigurator *config = [SNTConfigurator configurator];

  if (![config exportMetrics]) {
    return;
  }

  if (metrics == nil) {
    LOGE(@"nil metrics dictionary sent for export");
    return;
  }

  NSError *err;
  NSArray<NSData *> *formattedMetrics = [self convertMetrics:metrics
                                                    toFormat:config.metricFormat
                                                       error:&err];

  if (err != nil) {
    LOGE(@"unable to format metrics as  %@", [self messageFromError:err]);
    return;
  }

  const id writer = metricWriters[config.metricURL.scheme];

  if (writer) {
    BOOL ok = [writer write:formattedMetrics toURL:config.metricURL error:&err];

    if (!ok) {
      if (err != nil) {
        LOGE(@"unable to write metrics: %@", [self messageFromError:err]);
      }
    }
  }
}
@end
