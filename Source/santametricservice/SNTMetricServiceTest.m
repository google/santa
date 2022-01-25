#import <XCTest/XCTest.h>
#include <unistd.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"

#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>
#import <OCMock/OCMock.h>

#import "Source/santametricservice/Formats/SNTMetricFormatTestHelper.h"
#import "Source/santametricservice/SNTMetricService.h"

NSDictionary *validMetricsDict = nil;

@interface SNTMetricServiceTest : XCTestCase
@property id mockConfigurator;
@property NSString *tempDir;
@property NSURL *jsonURL;
@property id mockSession;
@property id mockSessionDataTask;
@property id mockMOLAuthenticatingURLSession;
@end

@implementation SNTMetricServiceTest

- (void)setUp {
  // create the configurator
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // create a temp dir
  char template[] = "/tmp/sntmetricsservicetestdata.XXXXXXX";
  char *tempPath = mkdtemp(template);

  XCTAssertNotEqual(tempPath, NULL, @"Unable to make temp dir");

  self.tempDir =
    [[NSFileManager defaultManager] stringWithFileSystemRepresentation:tempPath
                                                                length:strlen(tempPath)];
  self.jsonURL = [NSURL fileURLWithPathComponents:@[ self.tempDir, @"test.json" ]];
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];

  // delete the temp dir
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:NULL];
}

- (NSDate *)createNSDateFromDateString:(NSString *)dateString {
  NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
  formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
  formatter.calendar = [NSCalendar calendarWithIdentifier:NSCalendarIdentifierISO8601];
  formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];

  return [formatter dateFromString:dateString];
}

- (NSDictionary *)convertJSONDateStringsToNSDateWithJson:(NSDictionary *)jsonData {
  NSMutableDictionary *jsonDict = [jsonData mutableCopy];

  for (NSString *metricName in jsonDict[@"metrics"]) {
    NSMutableDictionary *metric = jsonDict[@"metrics"][metricName];

    for (NSString *field in metric[@"fields"]) {
      NSMutableArray<NSMutableDictionary *> *values = metric[@"fields"][field];

      for (int i = 0; i < values.count; ++i) {
        values[i][@"created"] = [self createNSDateFromDateString:values[i][@"created"]];
        values[i][@"last_updated"] = [self createNSDateFromDateString:values[i][@"last_updated"]];
      }
    }
  }

  return jsonDict;
}

- (void)testDefaultConfigOptionsDoNotExport {
  SNTMetricService *ms = [[SNTMetricService alloc] init];

  [ms exportForMonitoring:validMetricsDict];

  // Check the temp dir
  NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.tempDir
                                                                       error:NULL];
  XCTAssertEqual(0, items.count, @"found unexpected files in %@", self.tempDir);
}

- (void)testWritingRawJSONFile {
  OCMStub([self.mockConfigurator exportMetrics]).andReturn(YES);
  OCMStub([self.mockConfigurator metricFormat]).andReturn(SNTMetricFormatTypeRawJSON);
  OCMStub([self.mockConfigurator metricURL]).andReturn(self.jsonURL);

  SNTMetricService *ms = [[SNTMetricService alloc] init];
  NSDictionary *validMetricsDict = [SNTMetricFormatTestHelper createValidMetricsDictionary];

  [ms exportForMonitoring:validMetricsDict];

  // Ensure that this has written 1 file that is well formed.
  NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.tempDir
                                                                       error:NULL];
  XCTAssertEqual(1, items.count, @"failed to create JSON metrics file");

  NSData *jsonData = [NSData dataWithContentsOfFile:self.jsonURL.path
                                            options:NSDataReadingUncached
                                              error:nil];

  NSDictionary *parsedJSONData =
    [NSJSONSerialization JSONObjectWithData:jsonData
                                    options:NSJSONReadingMutableContainers
                                      error:nil];

  // Convert JSON's date strings back into dates.
  [self convertJSONDateStringsToNSDateWithJson:parsedJSONData];

  XCTAssertEqualObjects(validMetricsDict, parsedJSONData, @"invalid JSON created");
}

- (void)testWritingJSONOverHTTP {
  NSURL *url = [NSURL URLWithString:@"http://localhost:9444"];
  OCMStub([self.mockConfigurator exportMetrics]).andReturn(YES);
  OCMStub([self.mockConfigurator metricFormat]).andReturn(SNTMetricFormatTypeRawJSON);
  OCMStub([self.mockConfigurator metricURL]).andReturn(url);

  self.mockSession = OCMClassMock([NSURLSession class]);
  self.mockSessionDataTask = OCMClassMock([NSURLSessionDataTask class]);
  self.mockMOLAuthenticatingURLSession = OCMClassMock([MOLAuthenticatingURLSession class]);

  OCMStub([self.mockMOLAuthenticatingURLSession alloc])
    .andReturn(self.mockMOLAuthenticatingURLSession);
  OCMStub([self.mockMOLAuthenticatingURLSession session]).andReturn(self.mockSession);

  NSHTTPURLResponse *response =
    [[NSHTTPURLResponse alloc] initWithURL:url
                                statusCode:200
                               HTTPVersion:@"HTTP/1.1"
                              headerFields:@{@"content-type" : @"application/json"}];

  __unsafe_unretained __block void (^passedBlock)(NSData *, NSURLResponse *, NSError *);

  XCTestExpectation *responseCallback =
    [[XCTestExpectation alloc] initWithDescription:@"ensure writer passed JSON"];

  // stub out session to call completion handler immediately.
  OCMStub([(NSURLSessionDataTask *)self.mockSessionDataTask resume]).andDo(^(NSInvocation *inv) {
    if (passedBlock) {
      passedBlock(nil, response, nil);
    }
    [responseCallback fulfill];
  });

  // stub out NSURLSession to assign our completion handler and return our mock
  OCMStub([self.mockSession dataTaskWithRequest:[OCMArg any] completionHandler:[OCMArg any]])
    .andDo(^(NSInvocation *inv) {
      [inv retainArguments];
      [inv getArgument:&passedBlock atIndex:3];
    })
    .andReturn(self.mockSessionDataTask);

  SNTMetricService *service = [[SNTMetricService alloc] init];
  [service exportForMonitoring:[SNTMetricFormatTestHelper createValidMetricsDictionary]];
  [self waitForExpectations:@[ responseCallback ] timeout:10.0];
}

- (void)testWritingMonarchJSONToAFile {
  OCMStub([self.mockConfigurator exportMetrics]).andReturn(YES);
  OCMStub([self.mockConfigurator metricFormat]).andReturn(SNTMetricFormatTypeMonarchJSON);
  OCMStub([self.mockConfigurator metricURL]).andReturn(self.jsonURL);

  SNTMetricService *ms = [[SNTMetricService alloc] init];
  NSDictionary *validMetricsDict = [SNTMetricFormatTestHelper createValidMetricsDictionary];

  [ms exportForMonitoring:validMetricsDict];

  NSError *err;

  // Ensure that this has written 1 file that is well formed.
  NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.tempDir
                                                                       error:&err];
  XCTAssertNil(err);
  XCTAssertEqual(1, items.count, @"failed to create JSON metrics file");

  NSData *jsonData = [NSData dataWithContentsOfFile:self.jsonURL.path
                                            options:NSDataReadingUncached
                                              error:&err];
  XCTAssertNil(err);

  // Read expected result from a golden file.
  NSString *path = [[NSBundle bundleForClass:[self class]] resourcePath];
  path = [path stringByAppendingPathComponent:@"testdata/json/monarch.json"];

  NSData *goldenFileData = [NSData dataWithContentsOfFile:path
                                                  options:NSDataReadingUncached
                                                    error:&err];
  XCTAssertNil(err);
  XCTAssertNotNil(goldenFileData, @"unable to open / read golden file");

  NSDictionary *parsedJSONAsDict =
    [NSJSONSerialization JSONObjectWithData:jsonData
                                    options:NSJSONReadingMutableContainers
                                      error:&err];
  XCTAssertNil(err);

  NSDictionary *expectedJSONAsDict =
    [NSJSONSerialization JSONObjectWithData:goldenFileData
                                    options:NSJSONReadingMutableContainers
                                      error:&err];
  XCTAssertNil(err);

  XCTAssertEqualObjects(expectedJSONAsDict, parsedJSONAsDict, @"invalid JSON created");
}
@end
