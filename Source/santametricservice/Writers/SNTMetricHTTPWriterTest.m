#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>
#import <OCMock/OCMock.h>

#import "Source/santametricservice/Writers/SNTMetricHTTPWriter.h"

@interface SNTMetricHTTPWriterTest : XCTestCase
@property id mockSession;
@property id mockSessionDataTask;
@property id mockMOLAuthenticatingURLSession;
@property SNTMetricHTTPWriter *httpWriter;
@end

@implementation SNTMetricHTTPWriterTest

- (void)setUp {
  self.mockSession = [OCMockObject niceMockForClass:[NSURLSession class]];
  self.mockSessionDataTask = [OCMockObject niceMockForClass:[NSURLSessionDataTask class]];
  self.mockMOLAuthenticatingURLSession =
    [OCMockObject niceMockForClass:[MOLAuthenticatingURLSession class]];
  [[[self.mockMOLAuthenticatingURLSession stub] andReturn:self.mockMOLAuthenticatingURLSession]
    alloc];
  [[[self.mockMOLAuthenticatingURLSession stub] andReturn:self.mockSession] session];

  self.httpWriter = [[SNTMetricHTTPWriter alloc] init];
}

- (void)tearDown {
  [self.mockSessionDataTask stopMocking];
  [self.mockSession stopMocking];
  [self.mockMOLAuthenticatingURLSession stopMocking];
}

- (void)createMockResponseWithURL:(NSURL *)url
                         withCode:(NSInteger)code
                         withData:(NSData *)data
                        withError:(NSError *)err {
  NSHTTPURLResponse *response =
    [[NSHTTPURLResponse alloc] initWithURL:url
                                statusCode:code
                               HTTPVersion:@"HTTP/1.1"
                              headerFields:@{@"content-type" : @"application/json"}];

  __block void (^passedBlock)(NSData *, NSURLResponse *, NSError *);

  void (^getCompletionHandler)(NSInvocation *) = ^(NSInvocation *invocation) {
    [invocation getArgument:&passedBlock atIndex:3];
  };

  void (^callCompletionHandler)(NSInvocation *) = ^(NSInvocation *invocation) {
    passedBlock(data, response, err);
  };

  // stub out session to call completion handler immediately.
  [(NSURLSessionDataTask *)[[self.mockSessionDataTask stub] andDo:callCompletionHandler] resume];

  // stub out NSURLSession to assign our completion handler and return our mock
  [[[[self.mockSession stub] andDo:getCompletionHandler] andReturn:self.mockSessionDataTask]
    dataTaskWithRequest:[OCMArg any]
      completionHandler:[OCMArg any]];
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

  for (long code = 400; code < 600; code += 100) {
    [self createMockResponseWithURL:url withCode:code withData:nil withError:nil];

    BOOL result = [self.httpWriter write:@[ JSONdata ] toURL:url error:&err];

    XCTAssertEqual(NO, result, @"result of call to write did not fail as expected");
    XCTAssertNotNil(err);
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
  XCTAssertEqualObjects(@"received http status code 505 from http://localhost:9444",
                        err.userInfo[NSLocalizedDescriptionKey]);
}

- (void)testEnsurePassingNilOrNullErrorDoesNotCrash {
  NSURL *url = [NSURL URLWithString:@"http://localhost:9444"];

  // Ensure that non-200 status codes codes do not crash
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

  [self createMockResponseWithURL:url withCode:500 withData:nil withError:mockErr];

  result = [self.httpWriter write:@[ JSONdata ] toURL:url error:nil];
  XCTAssertFalse(result);

  result = [self.httpWriter write:@[ JSONdata ] toURL:url error:NULL];

  XCTAssertFalse(result);
}
@end
