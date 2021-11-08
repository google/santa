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

  typedef void (^dataTaskCompletion)(NSData *, NSURLResponse *, NSError *);
  typedef id (^completionHandler)(NSURLSession *, NSURLRequest *, dataTaskCompletion);

  __block dataTaskCompletion passedBlock;

  XCTestExpectation *responseCallback =
    [[XCTestExpectation alloc] initWithDescription:@"ensure writer passed JSON"];

  // stub out session to call completion handler immediately.
  OCMStub([(NSURLSessionDataTask *)self.mockSessionDataTask resume])
    .andDo(^void(NSURLSessionDataTask *unused) {
      passedBlock(nil, response, nil);
      [responseCallback fulfill];
    });

  // stub out NSURLSession to assign our completion handler and return our mock
  OCMStub([self.mockSession dataTaskWithRequest:[OCMArg any] completionHandler:[OCMArg any]])
    .andDo(
      ^id(NSURLSession *localSelf, NSURLRequest *request, dataTaskCompletion completionHandler) {
        passedBlock = completionHandler;
        return nil;
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
