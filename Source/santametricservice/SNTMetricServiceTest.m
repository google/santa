#import <XCTest/XCTest.h>
#include <unistd.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"

#import <OCMock/OCMock.h>
#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>

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
    if (self.mockSessionDataTask != nil) {
        [self.mockSessionDataTask stopMocking];
    }
    if (self.mockSession != nil) {
        [self.mockSession stopMocking];
    }
    if (self.mockMOLAuthenticatingURLSession != nil) {
        [self.mockMOLAuthenticatingURLSession stopMocking];
    }

  // delete the temp dir
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:NULL];
}

- (NSDate *)createNSDateFromDateString:(NSString *)dateString {
  NSDateFormatter *formatter = [[NSDateFormatter alloc] init];

  [formatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
  [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"];

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

- (void)testWritingJSON {
  NSURL *url = [NSURL URLWithString:@"http://localhost:9444"];
  OCMStub([self.mockConfigurator exportMetrics]).andReturn(YES);
  OCMStub([self.mockConfigurator metricFormat]).andReturn(SNTMetricFormatTypeRawJSON);
  OCMStub([self.mockConfigurator metricURL]).andReturn(url);

  self.mockSession = [OCMockObject niceMockForClass:[NSURLSession class]];
  self.mockSessionDataTask = [OCMockObject niceMockForClass:[NSURLSessionDataTask class]];
  self.mockMOLAuthenticatingURLSession =
    [OCMockObject niceMockForClass:[MOLAuthenticatingURLSession class]];
    
  [[[self.mockMOLAuthenticatingURLSession stub] andReturn:self.mockMOLAuthenticatingURLSession] alloc];
  [[[self.mockMOLAuthenticatingURLSession stub] andReturn:self.mockSession] session];

  NSHTTPURLResponse *response =
    [[NSHTTPURLResponse alloc] initWithURL:url
                                statusCode:200
                               HTTPVersion:@"HTTP/1.1"
                              headerFields:@{@"content-type" : @"application/json"}];

  __block void (^passedBlock)(NSData *, NSURLResponse *, NSError *);

  XCTestExpectation *responseCallback = [[XCTestExpectation alloc] initWithDescription:@"ensure writer passed JSON"];

  void (^getCompletionHandler)(NSInvocation *) = ^(NSInvocation *invocation) {
    [invocation getArgument:&passedBlock atIndex:3];
  };

  void (^callCompletionHandler)(NSInvocation *) = ^(NSInvocation *invocation) {
    passedBlock(nil, response, nil);
    [responseCallback fulfill];
  };
    

  // stub out session to call completion handler immediately.
  [(NSURLSessionDataTask *)[[self.mockSessionDataTask stub] andDo:callCompletionHandler] resume];

  // stub out NSURLSession to assign our completion handler and return our mock
  [[[[self.mockSession stub] andDo:getCompletionHandler] andReturn:self.mockSessionDataTask]
    dataTaskWithRequest:[OCMArg any]
      completionHandler:[OCMArg any]];

  SNTMetricService *service = [[SNTMetricService alloc] init];
  [service exportForMonitoring:[SNTMetricFormatTestHelper createValidMetricsDictionary]];
  [self waitForExpectations:@[responseCallback] timeout:10.0];
}
@end

