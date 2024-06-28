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

#import "Source/santametricservice/Formats/SNTMetricMonarchJSONFormat.h"

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"

const NSString *kMetricsCollection = @"metricsCollection";
const NSString *kMetricsDataSet = @"metricsDataSet";
const NSString *kMetricName = @"metricName";
const NSString *kStreamKind = @"streamKind";
const NSString *kValueType = @"valueType";
const NSString *kDescription = @"description";
const NSString *kData = @"data";
const NSString *kField = @"field";
const NSString *kFieldDescriptor = @"fieldDescriptor";
const NSString *kBoolValue = @"boolValue";
const NSString *kBoolValueType = @"BOOL";
const NSString *kInt64Value = @"int64Value";
const NSString *kInt64ValueType = @"INT64";
const NSString *kStringValue = @"stringValue";
const NSString *kStringValueType = @"STRING";
const NSString *kName = @"name";
const NSString *kStartTimestamp = @"startTimestamp";
const NSString *kEndTimestamp = @"endTimestamp";
const NSString *kRootLabels = @"rootLabels";
const NSString *kKey = @"key";

@implementation SNTMetricMonarchJSONFormat {
  NSISO8601DateFormatter *_dateFormatter;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _dateFormatter = [[NSISO8601DateFormatter alloc] init];
    _dateFormatter.formatOptions =
      NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
  }
  return self;
}

- (void)encodeValueTypeAndStreamKindFor:(NSString *)metricName
                             withMetric:(NSDictionary *)metric
                                   into:(NSMutableDictionary *)monarchMetric {
  if (!metric[@"type"]) {
    LOGE(@"metric type not supposed to be nil for %@", metricName);
    return;
  }

  NSNumber *type = metric[@"type"];
  if (![type isKindOfClass:[NSNumber class]]) {
    LOGE(@"%@ [@\"type\"] is not a number", metricName);
    return;
  }

  switch ((SNTMetricType)[type intValue]) {
    case SNTMetricTypeConstantBool: monarchMetric[kValueType] = kBoolValueType; break;
    case SNTMetricTypeConstantString: monarchMetric[kValueType] = kStringValueType; break;
    case SNTMetricTypeConstantInt64: monarchMetric[kValueType] = kInt64ValueType; break;
    case SNTMetricTypeConstantDouble: monarchMetric[kValueType] = @"DOUBLE"; break;
    case SNTMetricTypeGaugeBool:
      monarchMetric[kStreamKind] = @"GAUGE";
      monarchMetric[kValueType] = kBoolValueType;
      break;
    case SNTMetricTypeGaugeString:
      monarchMetric[kStreamKind] = @"GAUGE";
      monarchMetric[kValueType] = kStringValueType;
      break;
    case SNTMetricTypeGaugeInt64:
      monarchMetric[kStreamKind] = @"GAUGE";
      monarchMetric[kValueType] = kInt64ValueType;
      break;
    case SNTMetricTypeGaugeDouble:
      monarchMetric[kStreamKind] = @"GAUGE";
      monarchMetric[kValueType] = @"DOUBLE";
      break;
    case SNTMetricTypeCounter:
      monarchMetric[kStreamKind] = @"CUMULATIVE";
      monarchMetric[kValueType] = kInt64ValueType;
      break;
    default:
      LOGE(@"encountered unknown SNTMetricType - %ld for %@", (SNTMetricType)metric[@"type"],
           metricName);
      break;
  }
}

- (NSArray<NSDictionary *> *)encodeDataForMetric:(NSDictionary *)metric
                                withEndTimestamp:(NSDate *)endTimestamp {
  NSMutableArray<NSDictionary *> *monarchMetricData = [[NSMutableArray alloc] init];

  for (NSString *fieldName in metric[@"fields"]) {
    for (NSDictionary *entry in metric[@"fields"][fieldName]) {
      NSMutableDictionary *monarchDataEntry = [[NSMutableDictionary alloc] init];

      if (![fieldName isEqualToString:@""]) {
        // We encode multiple fields as a single comma separated string.
        NSArray<NSString *> *fieldNames = [fieldName componentsSeparatedByString:@","];
        NSArray<NSString *> *fieldValues = [entry[@"value"] componentsSeparatedByString:@","];

        if (fieldNames.count != fieldValues.count) {
          LOGE(@"malformed metric data encountered: %@", fieldName);
          continue;
        }
        monarchDataEntry[kField] = [[NSMutableArray alloc] init];

        for (int i = 0; i < fieldNames.count; i++) {
          [monarchDataEntry[kField]
            addObject:@{kName : fieldNames[i], kStringValue : fieldValues[i]}];
        }
      }

      monarchDataEntry[kStartTimestamp] = [self->_dateFormatter stringFromDate:entry[@"created"]];
      // Monarch wants all the end timestamp to be updated, even if the value does not change.
      monarchDataEntry[kEndTimestamp] = [self->_dateFormatter stringFromDate:endTimestamp];

      if (!metric[@"type"]) {
        LOGE(@"metric type is nil");
        continue;
      }

      NSNumber *type = metric[@"type"];

      switch ((SNTMetricType)[type intValue]) {
        case SNTMetricTypeConstantBool:
        case SNTMetricTypeGaugeBool: monarchDataEntry[kBoolValue] = entry[@"data"]; break;
        case SNTMetricTypeConstantInt64:
        case SNTMetricTypeGaugeInt64:
        case SNTMetricTypeCounter: monarchDataEntry[kInt64Value] = entry[@"data"]; break;
        case SNTMetricTypeConstantDouble:
        case SNTMetricTypeGaugeDouble: monarchDataEntry[@"doubleValue"] = entry[@"data"]; break;
        case SNTMetricTypeConstantString:
        case SNTMetricTypeGaugeString: monarchDataEntry[kStringValue] = entry[@"data"]; break;
        default: LOGE(@"encountered unknown SNTMetricType %ld", [type longValue]); break;
      }
      [monarchMetricData addObject:monarchDataEntry];
    }
  }

  return monarchMetricData;
}

/*
 * Translates SNTMetricSet fields to monarch's expected format. In this implementation only string
 * type fields are supported.
 */
- (NSArray<NSDictionary *> *)encodeFieldDescriptorsFor:(NSDictionary *)metric {
  NSMutableArray<NSDictionary *> *monarchFields = [[NSMutableArray alloc] init];

  for (NSString *field in metric[@"fields"]) {
    if (![field isEqualToString:@""]) {
      // we encode multiple field names as comma separated strings.
      NSArray<NSString *> *fieldNames = [field componentsSeparatedByString:@","];
      for (NSString *fieldName in fieldNames) {
        [monarchFields addObject:@{kName : fieldName, @"fieldType" : kStringValueType}];
      }
    }
  }
  return monarchFields;
}

/**
 * formatMetric translates the SNTMetricSet metric entries into those consumable
 * by Monarch.
 **/

- (NSDictionary *)formatMetric:(NSString *)name
                     withValue:(NSDictionary *)metric
               andEndtimestamp:(NSDate *)endTimestamp {
  NSMutableDictionary *monarchMetric = [[NSMutableDictionary alloc] init];

  monarchMetric[kMetricName] = name;

  if (metric[kDescription]) {
    monarchMetric[kDescription] = metric[kDescription];
  }

  NSArray<NSDictionary *> *fieldDescriptorEntries = [self encodeFieldDescriptorsFor:metric];
  if (fieldDescriptorEntries.count > 0) {
    monarchMetric[kFieldDescriptor] = fieldDescriptorEntries;
  }

  [self encodeValueTypeAndStreamKindFor:name withMetric:metric into:monarchMetric];
  monarchMetric[@"data"] = [self encodeDataForMetric:metric withEndTimestamp:endTimestamp];

  return monarchMetric;
}

/**
 * Normalizes the metrics dictionary for exporting to JSON
 **/
- (NSDictionary *)normalize:(NSDictionary *)metrics {
  NSMutableArray<NSDictionary *> *monarchMetrics = [[NSMutableArray alloc] init];
  NSDate *endTimestamp = [NSDate date];

  for (NSString *metricName in metrics[@"metrics"]) {
    [monarchMetrics addObject:[self formatMetric:metricName
                                       withValue:metrics[@"metrics"][metricName]
                                 andEndtimestamp:endTimestamp]];
  }

  NSMutableArray<NSDictionary *> *rootLabels = [[NSMutableArray alloc] init];

  for (NSString *keyName in metrics[@"root_labels"]) {
    [rootLabels addObject:@{kKey : keyName, kStringValue : metrics[@"root_labels"][keyName]}];
  }

  return @{kMetricsCollection : @[ @{kMetricsDataSet : monarchMetrics, kRootLabels : rootLabels} ]};
}

/*
 * Convert normalizes and converts the metrics dictionary to a JSON
 * object consumable by parts of Google Monarch's tooling.
 *
 * @param metrics an NSDictionary exported by the SNTMetricSet
 * @param error a pointer to an NSError to allow errors to bubble up.
 *
 * Returns an NSArray containing one entry of all metrics serialized to JSON or
 * nil on error.
 */
- (NSArray<NSData *> *)convert:(NSDictionary *)metrics error:(NSError **)err {
  NSDictionary *normalizedMetrics = [self normalize:metrics];

  NSData *json = [NSJSONSerialization dataWithJSONObject:normalizedMetrics
                                                 options:NSJSONWritingPrettyPrinted
                                                   error:err];

  if (json == nil || (err != nil && *err != nil)) {
    return nil;
  }

  return @[ json ];
}
@end
