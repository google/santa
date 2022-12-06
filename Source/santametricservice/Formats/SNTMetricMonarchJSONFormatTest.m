#import <XCTest/XCTest.h>

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import "Source/santametricservice/Formats/SNTMetricFormatTestHelper.h"
#import "Source/santametricservice/Formats/SNTMetricMonarchJSONFormat.h"

@interface SNTMetricMonarchJSONFormatTest : XCTestCase
@end

@implementation SNTMetricMonarchJSONFormatTest

- (void)testMetricsConversionToJSON {
  id classMock = OCMClassMock([NSDate class]);
  OCMStub([classMock date])
    .andReturn([NSDate dateWithTimeIntervalSince1970:1631826490]);  // 2021-09-16 21:08:10Z

  NSDictionary *validMetricsDict = [SNTMetricFormatTestHelper createValidMetricsDictionary];
  SNTMetricMonarchJSONFormat *formatter = [[SNTMetricMonarchJSONFormat alloc] init];
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
  path = [path stringByAppendingPathComponent:@"testdata/json/monarch.json"];

  NSData *goldenFileData = [NSData dataWithContentsOfFile:path];

  XCTAssertNotNil(goldenFileData, @"unable to open / read golden file");

  NSDictionary *expectedJSONDict =
    [NSJSONSerialization JSONObjectWithData:goldenFileData
                                    options:NSJSONReadingAllowFragments
                                      error:&err];

  XCTAssertNotNil(expectedJSONDict);
  XCTAssertNil(err);
  XCTAssertEqualObjects(expectedJSONDict, jsonDict, @"generated JSON does not match golden file.");
}

- (void)testPassingANilOrNullErrorDoesNotCrash {
  SNTMetricMonarchJSONFormat *formatter = [[SNTMetricMonarchJSONFormat alloc] init];
  NSDictionary *validMetricsDict = [SNTMetricFormatTestHelper createValidMetricsDictionary];

  [formatter convert:validMetricsDict error:nil];
  [formatter convert:validMetricsDict error:NULL];
}

@end
