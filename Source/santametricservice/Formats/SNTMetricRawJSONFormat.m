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
#import "Source/common/SNTLogging.h"

#import "Source/santametricservice/Formats/SNTMetricRawJSONFormat.h"

@implementation SNTMetricRawJSONFormat {
  NSDateFormatter *_dateFormatter;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _dateFormatter = [[NSDateFormatter alloc] init];
    [_dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"];
  }
  return self;
}

- (NSArray *)normalizeArray:(NSArray *)arr {
  NSMutableArray *normalized = [NSMutableArray arrayWithArray:arr];

  [normalized enumerateObjectsUsingBlock:^(id value, NSUInteger index, BOOL *stop) {
    if ([value isKindOfClass:[NSDate class]]) {
      normalized[index] = [self->_dateFormatter stringFromDate:(NSDate *)value];
    } else if ([value isKindOfClass:[NSArray class]]) {
      normalized[index] = [self normalizeArray:(NSArray *)value];
    } else if ([value isKindOfClass:[NSDictionary class]]) {
      normalized[index] = [self normalize:(NSDictionary *)value];
    }
  }];

  return normalized;
}

/**
 * Normalizes the metrics dictionary for exporting to JSON
 **/
- (NSDictionary *)normalize:(NSDictionary *)metrics {
  // Convert NSDate's to RFC3339 in strings as NSDate's cannot be serialized
  // to JSON.
  NSMutableDictionary *normalizedMetrics = [NSMutableDictionary dictionaryWithDictionary:metrics];

  [metrics enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
    if ([value isKindOfClass:[NSDate class]]) {
      normalizedMetrics[key] = [self->_dateFormatter stringFromDate:(NSDate *)value];
    } else if ([value isKindOfClass:[NSDictionary class]]) {
      normalizedMetrics[key] = [self normalize:(NSDictionary *)value];
    } else if ([value isKindOfClass:[NSArray class]]) {
      normalizedMetrics[key] = [self normalizeArray:(NSArray *)value];
    }
  }];

  return (NSDictionary *)normalizedMetrics;
}

/*
 * Convert normalies and converts the metrics dictionary to  a single JSON
 * object.
 *
 * @param metrics an NSDictionary exported by the SNTMetricSet
 * @param error a pointer to an NSError to allow errors to bubble up.
 *
 * Returns an NSArray containing one entry of all metrics serialized to JSON or
 * nil on error.
 */
- (NSArray<NSData *> *)convert:(NSDictionary *)metrics error:(NSError **)err {
  NSDictionary *normalizedMetrics = [self normalize:metrics];

  if (![NSJSONSerialization isValidJSONObject:normalizedMetrics]) {
    if (err != nil) {
      *err = [[NSError alloc]
        initWithDomain:@"SNTMetricRawJSONFileWriter"
                  code:EINVAL
              userInfo:@{
                NSLocalizedDescriptionKey : @"unable to convert metrics to JSON: invalid metrics"
              }];
    }
    return nil;
  }

  NSData *json = [NSJSONSerialization dataWithJSONObject:normalizedMetrics
                                                 options:NSJSONWritingPrettyPrinted
                                                   error:err];
  if (json == nil && *err != nil) {
    return nil;
  }

  return @[ json ];
}
@end
