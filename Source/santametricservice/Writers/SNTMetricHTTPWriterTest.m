#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>
#import <OCMock/OCMock.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santametricservice/Writers/SNTMetricHTTPWriter.h"

@interface SNTMetricHTTPWriterTest : XCTestCase
@property id mockSession;
@property id mockSessionDataTask;
@property id mockMOLAuthenticatingURLSession;
@property NSMutableArray<NSDictionary *> *mockResponses;
@property SNTMetricHTTPWriter *httpWriter;
@property id mockConfigurator;
@end

@implementation SNTMetricHTTPWriterTest

- (void)setUp {
  self.mockSession = OCMClassMock([NSURLSession class]);
  self.mockSessionDataTask = OCMClassMock([NSURLSessionDataTask class]);
  self.mockMOLAuthenticatingURLSession = OCMClassMock([MOLAuthenticatingURLSession class]);

  OCMStub([self.mockMOLAuthenticatingURLSession alloc])
    .andReturn(self.mockMOLAuthenticatingURLSession);
  OCMStub([self.mockMOLAuthenticatingURLSession session]).andReturn(self.mockSession);

  self.httpWriter = [[SNTMetricHTTPWriter alloc] init];
  self.mockResponses = [[NSMutableArray alloc] init];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // This must be marked __unsafe_unretained because we're going to store into
  // it using NSInvocation's getArgument:atIndex: method which takes a void*
  // to populate. If we don't mark the variable __unsafe_unretained it will
  // default to __strong and ARC will attempt to release the block when it goes
  // out of scope, not knowing that it wasn't ours to release in the first place.
  __unsafe_unretained __block void (^completionHandler)(NSData *, NSURLResponse *, NSError *);

  void (^getCompletionHandler)(NSInvocation *) = ^(NSInvocation *invocation) {
    [invocation getArgument:&completionHandler atIndex:3];
  };

  void (^callCompletionHandler)(NSInvocation *) = ^(NSInvocation *invocation) {
    NSDictionary *responseValue = self.mockResponses[0];
    if (responseValue != nil && completionHandler != nil) {
      completionHandler(responseValue[@"data"], responseValue[@"response"],
                        responseValue[@"error"]);
      [self.mockResponses removeObjectAtIndex:0];
    } else {
      XCTFail(@"mockResponses set to zero");
    }
  };

  OCMStub([(NSURLSessionDataTask *)self.mockSessionDataTask resume]).andDo(callCompletionHandler);

  OCMStub([self.mockSession dataTaskWithRequest:[OCMArg any] completionHandler:[OCMArg any]])
    .andDo(getCompletionHandler)
    .andReturn(self.mockSessionDataTask);
}

/// enqueues a mock HTTP response for testing.
- (void)createMockResponseWithURL:(NSURL *)url
                         withCode:(NSInteger)code
                         withData:(NSData *)data
                        withError:(NSError *)err {
  NSHTTPURLResponse *response =
    [[NSHTTPURLResponse alloc] initWithURL:url
                                statusCode:code
                               HTTPVersion:@"HTTP/1.1"
                              headerFields:@{@"content-type" : @"application/json"}];

  NSMutableDictionary *responseValue = [[NSMutableDictionary alloc] init];

  responseValue[@"data"] = data;
  responseValue[@"response"] = response;
  responseValue[@"error"] = err;

  [self.mockResponses addObject:responseValue];
}

- (void)testValidPostOfData {
  NSURL *url = [[NSURL alloc] initWithString:@"http://localhost:8444/submit"];

  [self createMockResponseWithURL:url withCode:200 withData:nil withError:nil];

  SNTMetricHTTPWriter *httpWriter = [[SNTMetricHTTPWriter alloc] init];

  NSData *JSONdata = [@"{\"foo\": \"bar\"}\r\n" dataUsingEncoding:NSUTF8StringEncoding];

  NSError *err;
  BOOL result = [httpWriter write:@[ JSONdata ] toURL:url error:&err];
  XCTAssertEqual(YES, result);
  XCTAssertNil(err);
}

- (void)testEnsureHTTPErrorCodesResultInErrors {
  NSURL *url = [NSURL URLWithString:@"http://localhost:10444"];

  NSData *JSONdata = [@"{\"foo\": \"bar\"}\r\n" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *err;

  for (NSInteger code = 400; code < 600; code += 100) {
    [self createMockResponseWithURL:url withCode:code withData:nil withError:nil];

    BOOL result = [self.httpWriter write:@[ JSONdata ] toURL:url error:&err];

    XCTAssertEqual(NO, result, @"result of call to write did not fail as expected");
    XCTAssertNotNil(err);
    XCTAssertEqual(code, err.code);
    XCTAssertEqual(@"com.google.santa.metricservice.writers.http", err.domain);

    NSString *expectedErrMsg = [NSString
      stringWithFormat:@"received http status code %ld from %@", code, url.absoluteString];
    XCTAssertEqualObjects(expectedErrMsg, err.localizedDescription);
    err = nil;
  }
}

- (void)testEnsureErrorsFromTransportAreHandled {
  NSURL *url = [NSURL URLWithString:@"http://localhost:9444"];
  NSError *mockErr = [[NSError alloc] initWithDomain:@"com.google.santa.metricservice.writers.http"
                                                code:505
                                            userInfo:@{NSLocalizedDescriptionKey : @"test error"}];
  NSError *err;

  [self createMockResponseWithURL:url withCode:505 withData:nil withError:mockErr];

  NSData *JSONdata = [@"{\"foo\": \"bar\"}\r\n" dataUsingEncoding:NSUTF8StringEncoding];

  BOOL result = [self.httpWriter write:@[ JSONdata ] toURL:url error:&err];

  XCTAssertEqual(NO, result, @"result of call to write did not fail as expected");
  XCTAssertEqual(mockErr.code, err.code);
  XCTAssertEqualObjects(mockErr.domain, err.domain);
  XCTAssertEqualObjects(@"test error", err.userInfo[NSLocalizedDescriptionKey]);
}

- (void)testEnsureMutlipleEntriesWriteMultipleTimes {
  NSURL *url = [NSURL URLWithString:@"http://localhost:9444"];

  // Ensure that non-200 status codes codes do not crash
  [self createMockResponseWithURL:url withCode:200 withData:nil withError:nil];
  [self createMockResponseWithURL:url withCode:200 withData:nil withError:nil];

  NSData *JSONdata = [@"{\"foo\": \"bar\"}\r\n" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *err;
  BOOL result = [self.httpWriter write:@[ JSONdata, JSONdata ] toURL:url error:&err];

  XCTAssertEqual(YES, result);
  XCTAssertNil(err);
  XCTAssertEqual(0, self.mockResponses.count, @"incorrect number of requests was made");
}

- (void)testEnsurePassingNilOrNullErrorDoesNotCrash {
  NSURL *url = [NSURL URLWithString:@"http://localhost:9444"];

  // Queue up two responses for nil and NULL.
  [self createMockResponseWithURL:url withCode:400 withData:nil withError:nil];
  [self createMockResponseWithURL:url withCode:400 withData:nil withError:nil];

  NSData *JSONdata = [@"{\"foo\": \"bar\"}\r\n" dataUsingEncoding:NSUTF8StringEncoding];

  BOOL result = [self.httpWriter write:@[ JSONdata ] toURL:url error:nil];
  XCTAssertEqual(NO, result);

  result = [self.httpWriter write:@[ JSONdata ] toURL:url error:NULL];
  XCTAssertEqual(NO, result);

  NSError *mockErr =
    [[NSError alloc] initWithDomain:@"com.google.santa.metricservice.writers.http.test"
                               code:505
                           userInfo:@{NSLocalizedDescriptionKey : @"test error"}];

  // Queue up two responses for nil and NULL.
  [self createMockResponseWithURL:url withCode:500 withData:nil withError:mockErr];
  [self createMockResponseWithURL:url withCode:500 withData:nil withError:mockErr];

  result = [self.httpWriter write:@[ JSONdata ] toURL:url error:nil];
  XCTAssertFalse(result);

  result = [self.httpWriter write:@[ JSONdata ] toURL:url error:NULL];

  XCTAssertFalse(result);
}

- (void)testEnsureTimeoutsDoNotCrashWriter {
  NSURL *url = [NSURL URLWithString:@"http://localhost:11444"];

  // Queue up two responses for nil and NULL.
  [self createMockResponseWithURL:url withCode:400 withData:nil withError:nil];
  // Set the timeout to 0 second
  OCMStub([self.mockConfigurator metricExportTimeout]).andReturn(0);

  NSData *JSONdata = [@"{\"foo\": \"bar\"}\r\n" dataUsingEncoding:NSUTF8StringEncoding];

  BOOL result = [self.httpWriter write:@[ JSONdata ] toURL:url error:nil];
  XCTAssertEqual(NO, result);
}
@end