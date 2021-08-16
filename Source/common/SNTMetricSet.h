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

/**
 * Provides an abstraction for various metric systems that will be exported to
 * monitoring systems via the MetricService. This is used to store internal
 * counters and metrics that can be exported to an external monitoring system.
 *
 * `SNTMetricSet` for storing and creating metrics and counters. This is
 *   the externally visible interface
 *   class.
 *
 *  Metric classes:
 *   * `SNTMetric` to store metric values broken down by "field" dimensions.
 *   * subclasses of `SNTMetric` with suitable setters:
 *     * `SNTMetricCounter`
 *     * `SNTMetricGaugeInt64`
 *     * `SNTMetricGaugeDouble`
 *     * `SNTMetricString`
 *     * `SNTMetricBool`
 */

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SNTMetricType) {
  SNTMetricTypeUnknown = 0,
  SNTMetricTypeConstantBool = 1,
  SNTMetricTypeConstantString = 2,
  SNTMetricTypeConstantInt64 = 3,
  SNTMetricTypeConstantDouble = 4,
  SNTMetricTypeGaugeBool = 5,
  SNTMetricTypeGaugeString = 6,
  SNTMetricTypeGaugeInt64 = 7,
  SNTMetricTypeGaugeDouble = 8,
  SNTMetricTypeCounter = 9,
};

@interface SNTMetric : NSObject
- (NSDictionary *)export;
@end

@interface SNTMetricCounter : SNTMetric
- (void)incrementBy:(long long)step forFieldValues:(NSArray<NSString *> *)fieldValues;
- (void)incrementForFieldValues:(NSArray<NSString *> *)fieldValues;
- (long long)getCountForFieldValues:(NSArray<NSString *> *)fieldValues;
@end

@interface SNTMetricInt64Gauge : SNTMetric
- (void)set:(long long)value forFieldValues:(NSArray<NSString *> *)fieldValues;
- (long long)getGaugeValueForFieldValues:(NSArray<NSString *> *)fieldValues;
@end

@interface SNTMetricDoubleGauge : SNTMetric
- (void)set:(double)value forFieldValues:(NSArray<NSString *> *)fieldValues;
- (double)getGaugeValueForFieldValues:(NSArray<NSString *> *)fieldValues;
@end

@interface SNTMetricStringGauge : SNTMetric
- (void)set:(NSString *)value forFieldValues:(NSArray<NSString *> *)fieldValues;
- (NSString *)getStringValueForFieldValues:(NSArray<NSString *> *)fieldValues;
@end

@interface SNTMetricBooleanGauge : SNTMetric
- (void)set:(BOOL)value forFieldValues:(NSArray<NSString *> *)fieldValues;
- (BOOL)getBoolValueForFieldValues:(NSArray<NSString *> *)fieldValues;
@end

/**
 * A registry of metrics with associated fields.
 */
@interface SNTMetricSet : NSObject
- (instancetype)initWithHostname:(NSString *)hostname username:(NSString *)username;

/* Returns a counter with the given name, field names and help
 *  text, registered with the MetricSet.
 *
 * @param name The counter name, for example @"/proc/cpu".
 * @param fieldNames The counter's field names, for example @[@"result"].
 * @param helpText The counter's help description.
 * @return A counter with the given specification registered with this root.
 *   The returned counter might have been created earlier with the same
 *   specification.
 * @throw NSInternalInconsistencyException When trying to register a second
 *   counter with the same name but a different schema as an existing one
 */
- (SNTMetricCounter *)counterWithName:(NSString *)name
                           fieldNames:(NSArray<NSString *> *)fieldNames
                             helpText:(NSString *)text;

- (void)addRootLabel:(NSString *)label value:(NSString *)value;

/**
 * Returns a int64 gauge metric with the given Streamz name and help text,
 * registered with this MetricSet.
 *
 * @param name The metric name, for example @"/memory/free".
 * @param fieldNames The metric's field names, for example @[@"type"].
 * @param helpText The metric's help description.
 */
- (SNTMetricInt64Gauge *)int64GaugeWithName:(NSString *)name
                                 fieldNames:(NSArray<NSString *> *)fieldNames
                                   helpText:(NSString *)helpText;

/**
 * Returns a double gauge metric with the given name and help text,
 * registered with this root.
 *
 * @param name The metric name, for example @"/memory/free".
 * @param fieldNames The metric's field names, for example @[@"type"].
 * @param helpText The metric's help description.
 */
- (SNTMetricDoubleGauge *)doubleGaugeWithName:(NSString *)name
                                   fieldNames:(NSArray<NSString *> *)fieldNames
                                     helpText:(NSString *)helpText;

/**
 * Returns a string gauge metric with the given name and help text,
 * registered with this metric set.
 *
 * @param name The metric name, for example @"/santa/mode".
 * @param fieldNames The metric's field names, for example @[@"type"].
 * @param helpText The metric's help description.
 */
- (SNTMetricStringGauge *)stringGaugeWithName:(NSString *)name
                                   fieldNames:(NSArray<NSString *> *)fieldNames
                                     helpText:(NSString *)helpText;

/**
 * Returns a boolean gauge metric with the given name and help text,
 * registered with this metric set.
 *
 * @param name The metric name, for example @"/memory/free".
 * @param fieldNames The metric's field names, for example @[@"type"].
 * @param helpText The metric's help description.
 */
- (SNTMetricBooleanGauge *)booleanGaugeWithName:(NSString *)name
                                     fieldNames:(NSArray<NSString *> *)fieldNames
                                       helpText:(NSString *)helpText;

/** Creates a constant metric with a string value and no fields. */
- (void)addConstantStringWithName:(NSString *)name
                         helpText:(NSString *)helpText
                            value:(NSString *)value;

/** Creates a constant metric with an integer value and no fields. */
- (void)addConstantIntegerWithName:(NSString *)name
                          helpText:(NSString *)helpText
                             value:(long long)value;

/** Creates a constant metric with an integer value and no fields. */
- (void)addConstantBooleanWithName:(NSString *)name helpText:(NSString *)helpText value:(BOOL)value;

/** Register a callback to get executed just before each export. */
- (void)registerCallback:(void (^)(void))callback;

/** Export creates an NSDictionary of the state of the metrics */
- (NSDictionary *)export;
@end

NS_ASSUME_NONNULL_END
