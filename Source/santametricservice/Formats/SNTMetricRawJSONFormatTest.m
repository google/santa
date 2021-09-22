#import <XCTest/XCTest.h>

#import "Source/common/SNTMetricSet.h"
#import "Source/santametricservice/Formats/SNTMetricRawJSONFormat.h"

NSDictionary *validMetricsDict = nil;

@interface SNTMetricRawJSONFormatTest : XCTestCase
@end

@implementation SNTMetricRawJSONFormatTest

- (void)initializeValidMetricsDict {
  NSDateFormatter *formatter = NSDateFormatter.new;
  [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"];
  NSDate *fixedDate = [formatter dateFromString:@"2021-09-16T21:07:34.826Z"];

  validMetricsDict = @{
    @"root_labels" : @{@"hostname" : @"testHost", @"username" : @"testUser"},
    @"metrics" : @{
      @"/build/label" : @{
        @"type" : @((int)SNTMetricTypeConstantString),
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : fixedDate,
            @"last_updated" : fixedDate,
            @"data" : @"20210809.0.1"
          } ]
        }
      },
      @"/santa/events" : @{
        @"type" : @((int)SNTMetricTypeCounter),
        @"fields" : @{
          @"rule_type" : @[
            @{
              @"value" : @"binary",
              @"created" : fixedDate,
              @"last_updated" : fixedDate,
              @"data" : @1,
            },
            @{
              @"value" : @"certificate",
              @"created" : fixedDate,
              @"last_updated" : fixedDate,
              @"data" : @2,
            },
          ],
        },
      },
      @"/santa/rules" : @{
        @"type" : @((int)SNTMetricTypeGaugeInt64),
        @"fields" : @{
          @"rule_type" : @[
            @{
              @"value" : @"binary",
              @"created" : fixedDate,
              @"last_updated" : fixedDate,
              @"data" : @1
            },
            @{
              @"value" : @"certificate",
              @"created" : fixedDate,
              @"last_updated" : fixedDate,
              @"data" : @3
            }
          ]
        },
      },
      @"/santa/using_endpoint_security_framework" : @{
        @"type" : @((int)SNTMetricTypeConstantBool),
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : fixedDate,
            @"last_updated" : fixedDate,
            @"data" : @YES,
          } ]
        }
      },
      @"/proc/birth_timestamp" : @{
        @"type" : @((int)SNTMetricTypeConstantInt64),
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : fixedDate,
            @"last_updated" : fixedDate,
            @"data" : @1250999830800L,
          } ]
        },
      },
      @"/proc/memory/virtual_size" : @{
        @"type" : @((int)SNTMetricTypeGaugeInt64),
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : fixedDate,
            @"last_updated" : fixedDate,
            @"data" : @987654321,
          } ]
        }
      },
      @"/proc/memory/resident_size" : @{
        @"type" : @((int)SNTMetricTypeGaugeInt64),
        @"fields" : @{
          @"" : @[ @{
            @"value" : @"",
            @"created" : fixedDate,
            @"last_updated" : fixedDate,
            @"data" : @123456789,
          } ]
        },
      },
    }
  };
}

- (void)setUp {
  [self initializeValidMetricsDict];
}

- (void)testMetricsConversionToJSON {
  SNTMetricRawJSONFormat *formatter = [[SNTMetricRawJSONFormat alloc] init];
  NSError *err = nil;
  NSArray<NSData *> *output = [formatter convert:validMetricsDict error:&err];

  XCTAssertEqual(1, output.count);
  XCTAssertNotNil(output[0]);
  XCTAssertNil(err);

  NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:output[0]
                                                           options:NSJSONReadingAllowFragments
                                                             error:&err];
  XCTAssertNotNil(jsonDict);

  NSString *path = [[NSBundle bundleForClass:[self class]] resourcePath];
  path = [path stringByAppendingPathComponent:@"testdata/json/test.json"];

  NSData *goldenFileData = [NSData dataWithContentsOfFile:path];

  XCTAssertNotNil(goldenFileData, @"unable to open / read golden file");

  NSDictionary *expectedJSONDict =
    [NSJSONSerialization JSONObjectWithData:goldenFileData
                                    options:NSJSONReadingAllowFragments
                                      error:&err];

  XCTAssertNotNil(expectedJSONDict);
  XCTAssertEqualObjects(expectedJSONDict, jsonDict, @"generated JSON does not match golden file.");
}

- (void)testPassingANilOrNullErrorDoesNotCrash {
  SNTMetricRawJSONFormat *formatter = [[SNTMetricRawJSONFormat alloc] init];

  NSArray<NSData *> *output = [formatter convert:validMetricsDict error:nil];
  output = [formatter convert:validMetricsDict error:NULL];
}

@end
