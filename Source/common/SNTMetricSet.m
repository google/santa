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

#import "SNTMetricSet.h"
#import "SNTCommonEnums.h"

NSString *SNTMetricMakeStringFromMetricType(SNTMetricType metricType) {
  NSString *typeStr;
  switch (metricType) {
    case SNTMetricTypeConstantBool: typeStr = @"SNTMetricTypeConstantBool"; break;
    case SNTMetricTypeConstantString: typeStr = @"SNTMetricTypeConstantString"; break;
    case SNTMetricTypeConstantInt64: typeStr = @"SNTMetricTypeConstantInt64"; break;
    case SNTMetricTypeConstantDouble: typeStr = @"SNTMetricTypeConstantDouble"; break;
    case SNTMetricTypeGaugeBool: typeStr = @"SNTMetricTypeGaugeBool"; break;
    case SNTMetricTypeGaugeString: typeStr = @"SNTMetricTypeGaugeString"; break;
    case SNTMetricTypeGaugeInt64: typeStr = @"SNTMetricTypeGaugeInt64"; break;
    case SNTMetricTypeGaugeDouble: typeStr = @"SNTMetricTypeGaugeDouble"; break;
    case SNTMetricTypeCounter: typeStr = @"SNTMetricTypeCounter"; break;
    default: typeStr = [NSString stringWithFormat:@"SNTMetricTypeUnknown %ld", metricType]; break;
  }
  return typeStr;
}

/**
 *  SNTMetricValue encapsulates the value of a metric along with the creation
 *  and update timestamps. It is thread-safe and has a separate field for each
 *  metric type.
 *
 *  It is intended to only be used by SNTMetrics;
 */
@interface SNTMetricValue : NSObject
/** Increment the counter by the step value, updating timestamps appropriately. */
- (void)addInt64:(long long)step;

/** Set the Int64 value. */
- (void)setInt64:(long long)value;

/** Set the double value. */
- (void)setDouble:(double)value;

/** Set the string value. */
- (void)setString:(NSString *)value;

/** Set the BOOL string value. */
- (void)setBool:(BOOL)value;

/**
 * Clears the last update timestamp.
 *
 * This makes the metric value always emit the current timestamp as last update timestamp.
 */
- (void)clearLastUpdateTimestamp;

/** Getters */
- (long long)getInt64Value;
- (double)getDoubleValue;
- (NSString *)getStringValue;
@end

@implementation SNTMetricValue {
  /** The int64 value for the SNTMetricValue, if set. */
  long long _int64Value;

  /** The double value for the SNTMetricValue, if set. */
  double _doubleValue;

  /** The string value for the SNTMetricValue, if set. */
  NSString *_stringValue;

  /** The boolean value for the SNTMetricValue, if set. */
  BOOL _boolValue;

  /** The first time this cell got created in the current process. */
  NSDate *_creationTime;

  /** The last time that the counter value was changed. */
  NSDate *_lastUpdate;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _creationTime = [NSDate date];
    _lastUpdate = _creationTime;
  }
  return self;
}

- (void)addInt64:(long long)step {
  @synchronized(self) {
    _int64Value += step;
    _lastUpdate = [NSDate date];
  }
}

- (void)setInt64:(long long)value {
  @synchronized(self) {
    _int64Value = value;
    _lastUpdate = [NSDate date];
  }
}

- (long long)getInt64Value {
  @synchronized(self) {
    return _int64Value;
  }
}

- (void)setDouble:(double)value {
  @synchronized(self) {
    _doubleValue = value;
    _lastUpdate = [NSDate date];
  }
}

- (double)getDoubleValue {
  @synchronized(self) {
    return _doubleValue;
  }
}

- (void)setString:(NSString *)value {
  @synchronized(self) {
    _stringValue = [value copy];
    _lastUpdate = [NSDate date];
  }
}

- (NSString *)getStringValue {
  @synchronized(self) {
    return [_stringValue copy];
  }
}

- (void)setBool:(BOOL)value {
  @synchronized(self) {
    _boolValue = value;
    _lastUpdate = [NSDate date];
  }
}

- (BOOL)getBoolValue {
  @synchronized(self) {
    return _boolValue;
  }
}

- (void)clearLastUpdateTimestamp {
  @synchronized(self) {
    _lastUpdate = nil;
  }
}

- (NSDate *)getLastUpdatedTimestamp {
  NSDate *updated = nil;
  @synchronized(self) {
    updated = [_lastUpdate copy];
  }
  return updated;
}

- (NSDate *)getCreatedTimestamp {
  NSDate *created = nil;
  @synchronized(self) {
    created = [_creationTime copy];
  }
  return created;
}
@end

@implementation SNTMetric {
 @private
  /** Fully qualified metric name e.g. /ops/security/santa. */
  NSString *_name;
  /** A help text for the metric to be exported to be exported. **/
  NSString *_help;

  /** Sorted list of the fieldNames **/
  NSArray<NSString *> *_fieldNames;
  /** Mapping of field values to actual metric values (e.g. metric /proc/cpu_usage @"mode"=@"user"
   * -> 0.89 */
  NSMutableDictionary<NSArray<NSString *> *, SNTMetricValue *> *_metricsForFieldValues;
  /** the type of metric this is e.g. counter, gauge etc. **/
  SNTMetricType _type;
}

- (instancetype)initWithName:(NSString *)name
                  fieldNames:(NSArray<NSString *> *)fieldNames
                    helpText:(NSString *)help
                        type:(SNTMetricType)type {
  self = [super init];
  if (self) {
    _name = [name copy];
    _help = [help copy];
    _fieldNames = [fieldNames copy];
    _metricsForFieldValues = [[NSMutableDictionary alloc] init];
    _type = type;
  }
  return self;
}

- (NSString *)name {
  return _name;
}

- (BOOL)hasSameSchemaAsMetric:(SNTMetric *)other {
  if (![other isKindOfClass:[self class]]) {
    return NO;
  }
  return [_name isEqualToString:other->_name] && [_help isEqualToString:other->_help] &&
         [_fieldNames isEqualTo:other->_fieldNames] && _type == other->_type;
}

/** Retrieves the SNTMetricValue for a given field value.
   Creates a new SNTMetricValue if none is present. */
- (SNTMetricValue *)metricValueForFieldValues:(NSArray<NSString *> *)fieldValues {
  NSParameterAssert(fieldValues.count == _fieldNames.count);
  SNTMetricValue *metricValue = nil;
  @synchronized(self) {
    metricValue = _metricsForFieldValues[fieldValues];

    if (!metricValue) {
      // Deep copy to prevent mutations to the keys we store in the dictionary.
      fieldValues = [fieldValues copy];
      metricValue = [[SNTMetricValue alloc] init];
      _metricsForFieldValues[fieldValues] = metricValue;
    }
  }

  return metricValue;
}

- (NSDictionary *)encodeMetricValueForFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = _metricsForFieldValues[fieldValues];

  NSMutableDictionary *fieldDict = [[NSMutableDictionary alloc] init];

  fieldDict[@"created"] = [metricValue getCreatedTimestamp];
  fieldDict[@"last_updated"] = [metricValue getLastUpdatedTimestamp];
  fieldDict[@"value"] = [fieldValues componentsJoinedByString:@","];

  switch (_type) {
    case SNTMetricTypeConstantBool:
    case SNTMetricTypeGaugeBool:
      fieldDict[@"data"] = [NSNumber numberWithBool:[metricValue getBoolValue]];
      break;
    case SNTMetricTypeConstantInt64:
    case SNTMetricTypeCounter:
    case SNTMetricTypeGaugeInt64:
      fieldDict[@"data"] = [NSNumber numberWithLongLong:[metricValue getInt64Value]];
      break;
    case SNTMetricTypeConstantDouble:
    case SNTMetricTypeGaugeDouble:
      fieldDict[@"data"] = [NSNumber numberWithDouble:[metricValue getDoubleValue]];
      break;
    case SNTMetricTypeConstantString:
    case SNTMetricTypeGaugeString: fieldDict[@"data"] = [metricValue getStringValue]; break;
    default: break;
  }
  return fieldDict;
}

- (NSDictionary *)export {
  NSMutableDictionary *metricDict = [NSMutableDictionary dictionaryWithCapacity:_fieldNames.count];
  metricDict[@"type"] = [NSNumber numberWithInt:(int)_type];
  metricDict[@"fields"] = [[NSMutableDictionary alloc] init];
  metricDict[@"description"] = [_help copy];

  if (_fieldNames.count == 0) {
    metricDict[@"fields"][@""] = @[ [self encodeMetricValueForFieldValues:@[]] ];
  } else {
    NSMutableArray *fieldVals = [[NSMutableArray alloc] init];

    for (NSArray<NSString *> *fieldValues in _metricsForFieldValues) {
      [fieldVals addObject:[self encodeMetricValueForFieldValues:fieldValues]];
    }
    metricDict[@"fields"][[_fieldNames componentsJoinedByString:@","]] = fieldVals;
  }
  return metricDict;
}
@end

@implementation SNTMetricCounter

- (instancetype)initWithName:(NSString *)name
                  fieldNames:(NSArray<NSString *> *)fieldNames
                    helpText:(NSString *)helpText {
  return [super initWithName:name
                  fieldNames:fieldNames
                    helpText:helpText
                        type:SNTMetricTypeCounter];
}

- (void)incrementBy:(long long)step forFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];

  if (!metricValue) {
    return;
  }
  [metricValue addInt64:step];
}

- (void)incrementForFieldValues:(NSArray<NSString *> *)fieldValues {
  [self incrementBy:1 forFieldValues:fieldValues];
}

- (long long)getCountForFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];

  if (!metricValue) {
    return -1;
  }

  return [metricValue getInt64Value];
}
@end

@implementation SNTMetricInt64Gauge
- (instancetype)initWithName:(NSString *)name
                  fieldNames:(NSArray<NSString *> *)fieldNames
                    helpText:(NSString *)helpText {
  return [super initWithName:name
                  fieldNames:fieldNames
                    helpText:helpText
                        type:SNTMetricTypeGaugeInt64];
}

- (void)set:(long long)value forFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];
  [metricValue setInt64:value];
}

- (long long)getGaugeValueForFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];

  if (!metricValue) {
    return -1;
  }

  return [metricValue getInt64Value];
}
@end

@implementation SNTMetricDoubleGauge

- (instancetype)initWithName:(NSString *)name
                  fieldNames:(NSArray<NSString *> *)fieldNames
                    helpText:(NSString *)text {
  return [super initWithName:name
                  fieldNames:fieldNames
                    helpText:text
                        type:SNTMetricTypeGaugeDouble];
}

- (void)set:(double)value forFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];
  [metricValue setDouble:value];
}

- (double)getGaugeValueForFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];

  if (!metricValue) {
    return -1;
  }

  return [metricValue getDoubleValue];
}
@end

@implementation SNTMetricStringGauge
- (instancetype)initWithName:(NSString *)name
                  fieldNames:(NSArray<NSString *> *)fieldNames
                    helpText:(NSString *)text {
  return [super initWithName:name
                  fieldNames:fieldNames
                    helpText:text
                        type:SNTMetricTypeGaugeString];
}

- (void)set:(NSString *)value forFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];
  [metricValue setString:value];
}

- (NSString *)getStringValueForFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];

  if (!metricValue) {
    return nil;
  }

  return [metricValue getStringValue];
}
@end

@implementation SNTMetricBooleanGauge
- (instancetype)initWithName:(NSString *)name
                  fieldNames:(NSArray<NSString *> *)fieldNames
                    helpText:(NSString *)helpText {
  return [super initWithName:name
                  fieldNames:fieldNames
                    helpText:helpText
                        type:SNTMetricTypeGaugeBool];
}

- (void)set:(BOOL)value forFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];
  [metricValue setBool:value];
}

- (BOOL)getBoolValueForFieldValues:(NSArray<NSString *> *)fieldValues {
  SNTMetricValue *metricValue = [self metricValueForFieldValues:fieldValues];

  if (!metricValue) {
    return false;
  }

  return [metricValue getBoolValue];
}
@end

/**
 *  SNTMetricSet is the top level container for all metrics and metrics value
 *  its is abstracted from specific implementations but is close to Google's
 *  Monarch and Prometheus formats.
 */
@implementation SNTMetricSet {
 @private
  /** Labels that are used to identify the entity to that all metrics apply to. */
  NSMutableDictionary<NSString *, NSString *> *_rootLabels;
  /** Registered metrics keyed by name */
  NSMutableDictionary<NSString *, SNTMetric *> *_metrics;

  /** Callbacks to update metric values before exporting metrics */
  NSMutableArray<void (^)(void)> *_callbacks;
}

+ (instancetype)sharedInstance {
  static SNTMetricSet *sharedMetrics;
  static dispatch_once_t onceToken;

  dispatch_once(&onceToken, ^{
    sharedMetrics = [[SNTMetricSet alloc] init];
  });

  return sharedMetrics;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _rootLabels = [[NSMutableDictionary alloc] init];
    _metrics = [[NSMutableDictionary alloc] init];
    _callbacks = [[NSMutableArray alloc] init];
  }
  return self;
}

- (instancetype)initWithHostname:(NSString *)hostname username:(NSString *)username {
  self = [super init];
  if (self) {
    _rootLabels = [[NSMutableDictionary alloc] init];
    _metrics = [[NSMutableDictionary alloc] init];
    _callbacks = [[NSMutableArray alloc] init];

    _rootLabels[@"hostname"] = [hostname copy];
    _rootLabels[@"username"] = [username copy];
  }

  return self;
}

- (void)reset {
  _metrics = [[NSMutableDictionary alloc] init];
}

- (void)addRootLabel:(NSString *)label value:(NSString *)value {
  @synchronized(self) {
    _rootLabels[label] = value;
  }
}

- (void)removeRootLabel:(NSString *)label {
  @synchronized(self) {
    [_rootLabels removeObjectForKey:label];
  }
}

- (SNTMetric *)registerMetric:(nonnull SNTMetric *)metric {
  @synchronized(self) {
    SNTMetric *oldMetric = _metrics[[metric name]];
    if ([oldMetric hasSameSchemaAsMetric:metric]) {
      return oldMetric;
    }
    NSAssert(!oldMetric, @"metric registered twice: %@", metric.name);
    _metrics[metric.name] = metric;
  }
  return metric;
}

- (void)registerCallback:(void (^)(void))callback {
  @synchronized(self) {
    [_callbacks addObject:callback];
  }
}

- (SNTMetricCounter *)counterWithName:(NSString *)name
                           fieldNames:(NSArray<NSString *> *)fieldNames
                             helpText:(NSString *)helpText {
  SNTMetricCounter *c = [[SNTMetricCounter alloc] initWithName:name
                                                    fieldNames:fieldNames
                                                      helpText:helpText];
  return (SNTMetricCounter *)[self registerMetric:c];
}

- (SNTMetricInt64Gauge *)int64GaugeWithName:(NSString *)name
                                 fieldNames:(NSArray<NSString *> *)fieldNames
                                   helpText:(NSString *)helpText {
  SNTMetricInt64Gauge *g = [[SNTMetricInt64Gauge alloc] initWithName:name
                                                          fieldNames:fieldNames
                                                            helpText:helpText];
  return (SNTMetricInt64Gauge *)[self registerMetric:g];
}

- (SNTMetricDoubleGauge *)doubleGaugeWithName:(NSString *)name
                                   fieldNames:(NSArray<NSString *> *)fieldNames
                                     helpText:(NSString *)helpText {
  SNTMetricDoubleGauge *g = [[SNTMetricDoubleGauge alloc] initWithName:name
                                                            fieldNames:fieldNames
                                                              helpText:helpText];

  return (SNTMetricDoubleGauge *)[self registerMetric:g];
}

- (SNTMetricStringGauge *)stringGaugeWithName:(NSString *)name
                                   fieldNames:(NSArray<NSString *> *)fieldNames
                                     helpText:(NSString *)helpText {
  SNTMetricStringGauge *s = [[SNTMetricStringGauge alloc] initWithName:name
                                                            fieldNames:fieldNames
                                                              helpText:helpText];

  return (SNTMetricStringGauge *)[self registerMetric:s];
}

- (SNTMetricBooleanGauge *)booleanGaugeWithName:(NSString *)name
                                     fieldNames:(NSArray<NSString *> *)fieldNames
                                       helpText:(NSString *)helpText {
  SNTMetricBooleanGauge *b = [[SNTMetricBooleanGauge alloc] initWithName:name
                                                              fieldNames:fieldNames
                                                                helpText:helpText];

  return (SNTMetricBooleanGauge *)[self registerMetric:b];
}

- (void)addConstantStringWithName:(NSString *)name
                         helpText:(NSString *)helpText
                            value:(NSString *)value {
  SNTMetric *metric = [[SNTMetric alloc] initWithName:name
                                           fieldNames:@[]
                                             helpText:helpText
                                                 type:SNTMetricTypeConstantString];

  SNTMetricValue *metricValue = [metric metricValueForFieldValues:@[]];
  [metricValue setString:value];
  [self registerMetric:metric];
}

- (void)addConstantIntegerWithName:(NSString *)name
                          helpText:(NSString *)helpText
                             value:(long long)value {
  SNTMetric *metric = [[SNTMetric alloc] initWithName:name
                                           fieldNames:@[]
                                             helpText:helpText
                                                 type:SNTMetricTypeConstantInt64];

  SNTMetricValue *metricValue = [metric metricValueForFieldValues:@[]];
  [metricValue setInt64:value];
  [self registerMetric:metric];
}

- (void)addConstantBooleanWithName:(NSString *)name
                          helpText:(NSString *)helpText
                             value:(BOOL)value {
  SNTMetric *metric = [[SNTMetric alloc] initWithName:name
                                           fieldNames:@[]
                                             helpText:helpText
                                                 type:SNTMetricTypeConstantBool];

  SNTMetricValue *metricValue = [metric metricValueForFieldValues:@[]];
  [metricValue setBool:value];
  [self registerMetric:metric];
}

/** Export current state of the SNTMetricSet as an NSDictionary. */
- (NSDictionary *)export {
  NSDictionary *exported = nil;

  // Invoke callbacks to ensure metrics are up to date.
  for (void (^cb)(void) in _callbacks) {
    cb();
  }

  @synchronized(self) {
    NSMutableDictionary *exportDict = [[NSMutableDictionary alloc] init];
    exportDict[@"root_labels"] = [_rootLabels copy];
    exportDict[@"metrics"] = [[NSMutableDictionary alloc] init];

    // TODO(markowsky) Sort the metrics so we always get the same output.
    for (NSString *metricName in _metrics) {
      exportDict[@"metrics"][metricName] = [_metrics[metricName] export];
    }

    exported = [NSDictionary dictionaryWithDictionary:exportDict];
  }
  return exported;
}

// Returns a human readble string from an SNTMetricFormat type
NSString *SNTMetricStringFromMetricFormatType(SNTMetricFormatType format) {
  switch (format) {
    case SNTMetricFormatTypeRawJSON: return @"rawjson";
    case SNTMetricFormatTypeMonarchJSON: return @"monarchjson";
    default: return @"Unknown Metric Format";
  }
}

NSDictionary *SNTMetricConvertDatesToISO8601Strings(NSDictionary *metrics) {
  NSMutableDictionary *mutableMetrics = [metrics mutableCopy];

  NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
  formatter.formatOptions =
    NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;

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

@end
