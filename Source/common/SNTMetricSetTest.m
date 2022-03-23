#import <XCTest/XCTest.h>

#import "Source/common/SNTMetricSet.h"

@interface SNTMetricCounterTest : XCTestCase
@end

@interface SNTMetricGaugeInt64Test : XCTestCase
@end

@interface SNTMetricDoubleGaugeTest : XCTestCase
@end

@interface SNTMetricBooleanGaugeTest : XCTestCase
@end

@interface SNTMetricStringGaugeTest : XCTestCase
@end

@interface SNTMetricSetTest : XCTestCase
@end

@interface SNTMetricSetHelperFunctionsTest : XCTestCase
@end

// Stub out NSDate's date method
@implementation NSDate (custom)

+ (instancetype)date {
  NSDateFormatter *formatter = NSDateFormatter.new;
  [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ssZZZ"];
  return [formatter dateFromString:@"2021-08-05 13:00:10+0000"];
}

@end

@implementation SNTMetricCounterTest
- (void)testSimpleCounter {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricCounter *c =
    [metricSet counterWithName:@"/santa/events"
                    fieldNames:@[ @"rule_type" ]
                      helpText:@"Count of exec events broken out by rule type."];

  XCTAssertNotNil(c, @"Expected returned SNTMetricCounter to not be nil");
  [c incrementForFieldValues:@[ @"certificate" ]];
  XCTAssertEqual(1, [c getCountForFieldValues:@[ @"certificate" ]],
                 @"Counter not incremented by 1");
  [c incrementBy:3 forFieldValues:@[ @"certificate" ]];
  XCTAssertEqual(4, [c getCountForFieldValues:@[ @"certificate" ]],
                 @"Counter not incremented by 3");
}

- (void)testExportNSDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricCounter *c =
    [metricSet counterWithName:@"/santa/events"
                    fieldNames:@[ @"rule_type" ]
                      helpText:@"Count of exec events broken out by rule type."];

  XCTAssertNotNil(c);
  [c incrementForFieldValues:@[ @"certificate" ]];

  NSDictionary *expected = @{
    @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeCounter],
    @"description" : @"Count of exec events broken out by rule type.",
    @"fields" : @{
      @"rule_type" : @[ @{
        @"value" : @"certificate",
        @"created" : [NSDate date],
        @"last_updated" : [NSDate date],
        @"data" : [NSNumber numberWithInt:1]
      } ]
    }
  };

  XCTAssertEqualObjects([c export], expected);
}

- (void)testAddingMetricWithSameSchema {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricCounter *a = [metricSet counterWithName:@"/santa/counter"
                                        fieldNames:@[]
                                          helpText:@"Test counter."];

  SNTMetricCounter *b = [metricSet counterWithName:@"/santa/counter"
                                        fieldNames:@[]
                                          helpText:@"Test counter."];

  XCTAssertEqual(a, b, @"Unexpected new counter returned.");
}
@end

@implementation SNTMetricBooleanGaugeTest
- (void)testSimpleGauge {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricBooleanGauge *b = [metricSet booleanGaugeWithName:@"/santa/daemon_connected"
                                                  fieldNames:@[]
                                                    helpText:@"Is the daemon connected."];
  XCTAssertNotNil(b);
  [b set:true forFieldValues:@[]];
  XCTAssertTrue([b getBoolValueForFieldValues:@[]]);
  [b set:false forFieldValues:@[]];
  XCTAssertFalse([b getBoolValueForFieldValues:@[]]);
}

- (void)testExportNSDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricBooleanGauge *b = [metricSet booleanGaugeWithName:@"/santa/daemon_connected"
                                                  fieldNames:@[]
                                                    helpText:@"Is the daemon connected."];
  XCTAssertNotNil(b);
  [b set:true forFieldValues:@[]];
  NSDictionary *expected = @{
    @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeBool],
    @"description" : @"Is the daemon connected.",
    @"fields" : @{
      @"" : @[ @{
        @"value" : @"",
        @"created" : [NSDate date],
        @"last_updated" : [NSDate date],
        @"data" : [NSNumber numberWithBool:true]
      } ]
    }
  };

  NSDictionary *output = [b export];
  XCTAssertEqualObjects(output, expected);
}

- (void)testAddingBooleanWithSameSchema {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricBooleanGauge *a = [metricSet booleanGaugeWithName:@"/santa/daemon_connected"
                                                  fieldNames:@[]
                                                    helpText:@"Is the daemon connected."];

  SNTMetricBooleanGauge *b = [metricSet booleanGaugeWithName:@"/santa/daemon_connected"
                                                  fieldNames:@[]
                                                    helpText:@"Is the daemon connected."];

  XCTAssertEqual(a, b, @"Unexpected new boolean gauge returned.");
}

@end

@implementation SNTMetricGaugeInt64Test
- (void)testSimpleGauge {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricInt64Gauge *g =
    [metricSet int64GaugeWithName:@"/santa/rules"
                       fieldNames:@[ @"rule_type" ]
                         helpText:@"Count of rules broken out by rule type."];

  XCTAssertNotNil(g, @"Expected returned SNTMetricGaugeInt64 to not be nil");
  // set from zero
  [g set:250 forFieldValues:@[ @"binary" ]];
  XCTAssertEqual(250, [g getGaugeValueForFieldValues:@[ @"binary" ]]);

  // Increase the gauge
  [g set:500 forFieldValues:@[ @"binary" ]];
  XCTAssertEqual(500, [g getGaugeValueForFieldValues:@[ @"binary" ]]);
  // Decrease after increase
  [g set:100 forFieldValues:@[ @"binary" ]];
  XCTAssertEqual(100, [g getGaugeValueForFieldValues:@[ @"binary" ]]);
  // Increase after decrease
  [g set:750 forFieldValues:@[ @"binary" ]];
  XCTAssertEqual(750, [g getGaugeValueForFieldValues:@[ @"binary" ]]);
  // TODO: export the tree to JSON and confirm the structure is correct.
}

- (void)testExportNSDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricInt64Gauge *g =
    [metricSet int64GaugeWithName:@"/santa/rules"
                       fieldNames:@[ @"rule_type" ]
                         helpText:@"Count of rules broken out by rule type."];

  XCTAssertNotNil(g, @"Expected returned SNTMetricGaugeInt64 to not be nil");
  // set from zero
  [g set:250 forFieldValues:@[ @"binary" ]];
  XCTAssertEqual(250, [g getGaugeValueForFieldValues:@[ @"binary" ]]);

  NSDictionary *expected = @{
    @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeInt64],
    @"description" : @"Count of rules broken out by rule type.",
    @"fields" : @{
      @"rule_type" : @[ @{
        @"value" : @"binary",
        @"created" : [NSDate date],
        @"last_updated" : [NSDate date],
        @"data" : [NSNumber numberWithInt:250]
      } ]
    }
  };

  XCTAssertEqualObjects([g export], expected);
}

- (void)testAddingMetricWithSameSchema {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricInt64Gauge *a = [metricSet int64GaugeWithName:@"/santa/int64gauge"
                                              fieldNames:@[]
                                                helpText:@"Test gauge."];

  SNTMetricInt64Gauge *b = [metricSet int64GaugeWithName:@"/santa/int64gauge"
                                              fieldNames:@[]
                                                helpText:@"Test gauge."];

  XCTAssertEqual(a, b, @"Unexpected new gauge returned.");
}

@end

@implementation SNTMetricDoubleGaugeTest

- (void)testSimpleGauge {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricDoubleGauge *g = [metricSet doubleGaugeWithName:@"/proc/cpu_usage"
                                                fieldNames:@[ @"mode" ]
                                                  helpText:@"CPU time consumed by this process."];

  XCTAssertNotNil(g, @"Expected returned SNTMetricDoubleGauge to not be nil");
  // set from zero
  [g set:(double)0.45 forFieldValues:@[ @"user" ]];
  XCTAssertEqual(0.45, [g getGaugeValueForFieldValues:@[ @"user" ]]);

  // Increase the gauge
  [g set:(double)0.90 forFieldValues:@[ @"user" ]];
  XCTAssertEqual(0.90, [g getGaugeValueForFieldValues:@[ @"user" ]]);
  // Decrease after increase
  [g set:0.71 forFieldValues:@[ @"user" ]];
  XCTAssertEqual(0.71, [g getGaugeValueForFieldValues:@[ @"user" ]]);
  // Increase after decrease
  [g set:0.75 forFieldValues:@[ @"user" ]];
  XCTAssertEqual(0.75, [g getGaugeValueForFieldValues:@[ @"user" ]]);
}

- (void)testExportNSDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricDoubleGauge *g = [metricSet doubleGaugeWithName:@"/proc/cpu_usage"
                                                fieldNames:@[ @"mode" ]
                                                  helpText:@"CPU time consumed by this process."];

  XCTAssertNotNil(g, @"Expected returned SNTMetricDoubleGauge to not be nil");
  // set from zero
  [g set:(double)0.45 forFieldValues:@[ @"user" ]];
  [g set:(double)0.90 forFieldValues:@[ @"system" ]];

  NSDictionary *expected = @{
    @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeDouble],
    @"description" : @"CPU time consumed by this process.",
    @"fields" : @{
      @"mode" : @[
        @{
          @"value" : @"user",
          @"created" : [NSDate date],
          @"last_updated" : [NSDate date],
          @"data" : [NSNumber numberWithDouble:0.45]
        },
        @{
          @"value" : @"system",
          @"created" : [NSDate date],
          @"last_updated" : [NSDate date],
          @"data" : [NSNumber numberWithDouble:0.90]
        }
      ]
    }
  };
  XCTAssertEqualObjects([g export], expected);
}

- (void)testAddingMetricWithSameSchema {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricDoubleGauge *a = [metricSet doubleGaugeWithName:@"/santa/doublegauge"
                                                fieldNames:@[]
                                                  helpText:@"Test gauge."];

  SNTMetricDoubleGauge *b = [metricSet doubleGaugeWithName:@"/santa/doublegauge"
                                                fieldNames:@[]
                                                  helpText:@"Test gauge."];

  XCTAssertEqual(a, b, @"Unexpected new gauge returned.");
}
@end

@implementation SNTMetricStringGaugeTest
- (void)testSimpleGauge {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricStringGauge *s = [metricSet stringGaugeWithName:@"/santa/mode"
                                                fieldNames:@[]
                                                  helpText:@"String description of the mode."];

  XCTAssertNotNil(s);
  [s set:@"testValue" forFieldValues:@[]];
  XCTAssertEqualObjects([s getStringValueForFieldValues:@[]], @"testValue");
}

- (void)testExportNSDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricStringGauge *s = [metricSet stringGaugeWithName:@"/santa/mode"
                                                fieldNames:@[]
                                                  helpText:@"String description of the mode."];

  XCTAssertNotNil(s);
  [s set:@"testValue" forFieldValues:@[]];

  NSDictionary *expected = @{
    @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeString],
    @"description" : @"String description of the mode.",
    @"fields" : @{
      @"" : @[ @{
        @"value" : @"",
        @"created" : [NSDate date],
        @"last_updated" : [NSDate date],
        @"data" : @"testValue"
      } ]
    }
  };

  XCTAssertEqualObjects([s export], expected);
}

- (void)testAddingMetricWithSameSchema {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricStringGauge *a = [metricSet stringGaugeWithName:@"/santa/stringgauge"
                                                fieldNames:@[]
                                                  helpText:@"Test gauge."];

  SNTMetricStringGauge *b = [metricSet stringGaugeWithName:@"/santa/stringgauge"
                                                fieldNames:@[]
                                                  helpText:@"Test gauge."];

  XCTAssertEqual(a, b, @"Unexpected new gauge returned.");
}

@end

@implementation SNTMetricSetTest
- (void)testRootLabels {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  [metricSet addRootLabel:@"hostname" value:@"localhost"];

  NSDictionary *expected = @{@"root_labels" : @{@"hostname" : @"localhost"}, @"metrics" : @{}};

  XCTAssertEqualObjects(expected, [metricSet export]);

  // ensure that adding a rootLabel with the same name overwrites.
  expected = @{@"root_labels" : @{@"hostname" : @"localhost2"}, @"metrics" : @{}};
  [metricSet addRootLabel:@"hostname" value:@"localhost2"];

  XCTAssertEqualObjects(expected, [metricSet export],
                        @"failed to overwrite rootLabel with second call to addRootLabel");

  // ensure that removing a rootLabelWorks
  expected = @{@"root_labels" : @{}, @"metrics" : @{}};
  [metricSet removeRootLabel:@"hostname"];
}

- (void)testDoubleRegisteringIncompatibleMetricsFails {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  SNTMetricCounter *c = [metricSet counterWithName:@"/foo/bar"
                                        fieldNames:@[ @"field" ]
                                          helpText:@"lorem ipsum"];

  XCTAssertNotNil(c);
  XCTAssertThrows([metricSet counterWithName:@"/foo/bar"
                                  fieldNames:@[ @"incompatible" ]
                                    helpText:@"A little help text"],
                  @"Should raise error for incompatible field names");

  XCTAssertThrows([metricSet counterWithName:@"/foo/bar"
                                  fieldNames:@[ @"result" ]
                                    helpText:@"INCOMPATIBLE"],
                  @"Should raise error for incompatible help text");
}

- (void)testRegisterCallback {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  // Register a callback metric which increments by one before export
  SNTMetricInt64Gauge *gauge = [metricSet int64GaugeWithName:@"/foo/bar"
                                                  fieldNames:@[]
                                                    helpText:@"Number of callbacks done"];
  __block int count = 0;
  [metricSet registerCallback:^(void) {
    count++;
    [gauge set:count forFieldValues:@[]];
  }];

  // ensure the callback is called.
  [metricSet export];

  XCTAssertEqual([gauge getGaugeValueForFieldValues:@[]], 1);
}

- (void)testAddConstantBool {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  [metricSet addConstantBooleanWithName:@"/tautology"
                               helpText:@"The first rule of tautology club is the first rule"
                                  value:YES];

  NSDictionary *expected = @{
    @"/tautology" : @{
      @"description" : @"The first rule of tautology club is the first rule",
      @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeConstantBool],
      @"fields" : @{
        @"" : @[ @{
          @"value" : @"",
          @"created" : [NSDate date],
          @"last_updated" : [NSDate date],
          @"data" : [NSNumber numberWithBool:true]
        } ]
      }
    }
  };

  XCTAssertEqualObjects([metricSet export][@"metrics"], expected);
}

- (void)testAddConstantString {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];

  [metricSet addConstantStringWithName:@"/build/label"
                              helpText:@"Build label for the binary"
                                 value:@"20210806.0.1"];

  NSDictionary *expected = @{
    @"/build/label" : @{
      @"description" : @"Build label for the binary",
      @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeConstantString],
      @"fields" : @{
        @"" : @[ @{
          @"value" : @"",
          @"created" : [NSDate date],
          @"last_updated" : [NSDate date],
          @"data" : @"20210806.0.1"
        } ]
      }
    }
  };

  XCTAssertEqualObjects([metricSet export][@"metrics"], expected);
}

- (void)testAddConstantInt {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] init];
  [metricSet addConstantIntegerWithName:@"/deep/thought/answer"
                               helpText:@"Life, the universe, and everything"
                                  value:42];

  NSDictionary *expected = @{
    @"/deep/thought/answer" : @{
      @"description" : @"Life, the universe, and everything",
      @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeConstantInt64],
      @"fields" : @{
        @"" : @[ @{
          @"value" : @"",
          @"created" : [NSDate date],
          @"last_updated" : [NSDate date],
          @"data" : [NSNumber numberWithLongLong:42]
        } ]
      }
    }
  };

  XCTAssertEqualObjects([metricSet export][@"metrics"], expected);
}

- (void)testExportNSDictionary {
  SNTMetricSet *metricSet = [[SNTMetricSet alloc] initWithHostname:@"testHost"
                                                          username:@"testUser"];

  // Add constants
  [metricSet addConstantStringWithName:@"/build/label"
                              helpText:@"Software version running."
                                 value:@"20210809.0.1"];
  [metricSet addConstantBooleanWithName:@"/santa/using_endpoint_security_framework"
                               helpText:@"Is santad using the endpoint security framework."
                                  value:TRUE];
  [metricSet
    addConstantIntegerWithName:@"/proc/birth_timestamp"
                      helpText:@"Start time of this santad instance, in microseconds since epoch"
                         value:(long long)(0x12345668910)];
  // Add Metrics
  SNTMetricCounter *c = [metricSet counterWithName:@"/santa/events"
                                        fieldNames:@[ @"rule_type" ]
                                          helpText:@"Count of events on the host"];

  [c incrementForFieldValues:@[ @"binary" ]];
  [c incrementBy:2 forFieldValues:@[ @"certificate" ]];

  SNTMetricInt64Gauge *g = [metricSet int64GaugeWithName:@"/santa/rules"
                                              fieldNames:@[ @"rule_type" ]
                                                helpText:@"Number of rules."];

  [g set:1 forFieldValues:@[ @"binary" ]];
  [g set:3 forFieldValues:@[ @"certificate" ]];

  // Add Metrics with callback
  SNTMetricInt64Gauge *virtualMemoryGauge =
    [metricSet int64GaugeWithName:@"/proc/memory/virtual_size"
                       fieldNames:@[]
                         helpText:@"The virtual memory size of this process."];

  SNTMetricInt64Gauge *residentMemoryGauge =
    [metricSet int64GaugeWithName:@"/proc/memory/resident_size"
                       fieldNames:@[]
                         helpText:@"The resident set size of this process."];

  [metricSet registerCallback:^(void) {
    [virtualMemoryGauge set:987654321 forFieldValues:@[]];
    [residentMemoryGauge set:123456789 forFieldValues:@[]];
  }];

  NSDictionary *expected = @{
    @"root_labels" : @{@"hostname" : @"testHost", @"username" : @"testUser"},
    @"metrics" : @{
      @"/build/label" : @{
        @"description" : @"Software version running.",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeConstantString],
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : [NSDate date],
            @"last_updated" : [NSDate date],
            @"data" : @"20210809.0.1"
          } ]
        }
      },
      @"/santa/events" : @{
        @"description" : @"Count of events on the host",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeCounter],
        @"fields" : @{
          @"rule_type" : @[
            @{
              @"value" : @"binary",
              @"created" : [NSDate date],
              @"last_updated" : [NSDate date],
              @"data" : [NSNumber numberWithInt:1],
            },
            @{
              @"value" : @"certificate",
              @"created" : [NSDate date],
              @"last_updated" : [NSDate date],
              @"data" : [NSNumber numberWithInt:2],
            },
          ],
        },
      },
      @"/santa/rules" : @{
        @"description" : @"Number of rules.",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeInt64],
        @"fields" : @{
          @"rule_type" : @[
            @{
              @"value" : @"binary",
              @"created" : [NSDate date],
              @"last_updated" : [NSDate date],
              @"data" : [NSNumber numberWithInt:1],
            },
            @{
              @"value" : @"certificate",
              @"created" : [NSDate date],
              @"last_updated" : [NSDate date],
              @"data" : [NSNumber numberWithInt:3],
            }
          ]
        },
      },
      @"/santa/using_endpoint_security_framework" : @{
        @"description" : @"Is santad using the endpoint security framework.",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeConstantBool],
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : [NSDate date],
            @"last_updated" : [NSDate date],
            @"data" : [NSNumber numberWithBool:YES]
          } ]
        }
      },
      @"/proc/birth_timestamp" : @{
        @"description" : @"Start time of this santad instance, in microseconds since epoch",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeConstantInt64],
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : [NSDate date],
            @"last_updated" : [NSDate date],
            @"data" : [NSNumber numberWithLong:1250999830800]
          } ]
        },
      },
      @"/proc/memory/virtual_size" : @{
        @"description" : @"The virtual memory size of this process.",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeInt64],
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : [NSDate date],
            @"last_updated" : [NSDate date],
            @"data" : [NSNumber numberWithInt:987654321]
          } ]
        }
      },
      @"/proc/memory/resident_size" : @{
        @"description" : @"The resident set size of this process.",
        @"type" : [NSNumber numberWithInt:(int)SNTMetricTypeGaugeInt64],
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : [NSDate date],
            @"last_updated" : [NSDate date],
            @"data" : [NSNumber numberWithInt:123456789]
          } ]
        },
      },
    }
  };

  XCTAssertEqualObjects([metricSet export], expected);
}
@end

@implementation SNTMetricSetHelperFunctionsTest
- (void)testMakeMetricString {
  NSArray<NSDictionary *> *tests = @[
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeUnknown],
      @"expected" : @"SNTMetricTypeUnknown 0"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeConstantBool],
      @"expected" : @"SNTMetricTypeConstantBool"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeConstantString],
      @"expected" : @"SNTMetricTypeConstantString"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeConstantInt64],
      @"expected" : @"SNTMetricTypeConstantInt64"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeConstantDouble],
      @"expected" : @"SNTMetricTypeConstantDouble"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeGaugeBool],
      @"expected" : @"SNTMetricTypeGaugeBool"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeGaugeString],
      @"expected" : @"SNTMetricTypeGaugeString"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeGaugeInt64],
      @"expected" : @"SNTMetricTypeGaugeInt64"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeGaugeDouble],
      @"expected" : @"SNTMetricTypeGaugeDouble"
    },
    @{
      @"input" : [NSNumber numberWithInt:SNTMetricTypeCounter],
      @"expected" : @"SNTMetricTypeCounter"
    }
  ];

  for (NSDictionary *test in tests) {
    NSString *output = SNTMetricMakeStringFromMetricType([test[@"input"] integerValue]);
    XCTAssertEqualObjects(test[@"expected"], output, @"expected %@ got %@", test[@"expected"],
                          output);
  }
}
@end
