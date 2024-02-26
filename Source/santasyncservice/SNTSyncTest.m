/// Copyright 2016 Google Inc. All rights reserved.
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

#include <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import <MOLXPCConnection/MOLXPCConnection.h>
#import <OCMock/OCMock.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncEventUpload.h"
#import "Source/santasyncservice/SNTSyncPostflight.h"
#import "Source/santasyncservice/SNTSyncPreflight.h"
#import "Source/santasyncservice/SNTSyncRuleDownload.h"
#import "Source/santasyncservice/SNTSyncStage.h"
#import "Source/santasyncservice/SNTSyncState.h"

// Prevent Zlib compression during testing
@implementation NSData (Zlib)
- (NSData *)zlibCompressed {
  return nil;
}
- (NSData *)gzipCompressed {
  return nil;
}
@end

@interface SNTSyncStage (XSSI)
- (NSData *)stripXssi:(NSData *)data;
@end

@interface SNTSyncTest : XCTestCase
@property SNTSyncState *syncState;
@property id<SNTDaemonControlXPC> daemonConnRop;
@end

@implementation SNTSyncTest

- (void)setUp {
  [super setUp];

  self.syncState = [[SNTSyncState alloc] init];
  self.syncState.daemonConn = OCMClassMock([MOLXPCConnection class]);
  self.daemonConnRop = OCMProtocolMock(@protocol(SNTDaemonControlXPC));
  OCMStub([self.syncState.daemonConn remoteObjectProxy]).andReturn(self.daemonConnRop);
  OCMStub([self.syncState.daemonConn synchronousRemoteObjectProxy]).andReturn(self.daemonConnRop);

  self.syncState.session = OCMClassMock([NSURLSession class]);

  self.syncState.syncBaseURL = [NSURL URLWithString:@"https://myserver.local/"];
  self.syncState.machineID = [[NSUUID UUID] UUIDString];
  self.syncState.machineOwner = NSUserName();
}

#pragma mark Test Helpers

/**
  Stub out dataTaskWithRequest:completionHandler:

  @param respData The HTTP body to return.
  @param resp The NSHTTPURLResponse to return. If nil, a basic 200 response will be sent.
  @param err The error object to return to the handler.
  @param validateBlock Use to validate the request is the one intended to be stubbed.
      Returning NO means this stub is not applied.
*/
- (void)stubRequestBody:(NSData *)respData
               response:(NSURLResponse *)resp
                  error:(NSError *)err
          validateBlock:(BOOL (^)(NSURLRequest *req))validateBlock {
  if (!respData) respData = (NSData *)[NSNull null];
  if (!resp) resp = [self responseWithCode:200 headerDict:nil];
  if (!err) err = (NSError *)[NSNull null];

  // Cast the value into an NSURLRequest to save callers doing it.
  BOOL (^validateBlockWrapper)(id value) = ^BOOL(id value) {
    if (!validateBlock) return YES;
    NSURLRequest *req = (NSURLRequest *)value;
    return validateBlock(req);
  };

  OCMStub([self.syncState.session
    dataTaskWithRequest:[OCMArg checkWithBlock:validateBlockWrapper]
      completionHandler:([OCMArg invokeBlockWithArgs:respData, resp, err, nil])]);
}

/**
  Generate an NSHTTPURLResponse with the provided HTTP status code and header dictionary.

  @param code The HTTP status code for this response
  @param headerDict A dictionary of HTTP headers to add to the response.
  @returns An initialized NSHTTPURLResponse.
*/
- (NSHTTPURLResponse *)responseWithCode:(NSInteger)code headerDict:(NSDictionary *)headerDict {
  return [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"a"]
                                     statusCode:code
                                    HTTPVersion:@"1.1"
                                   headerFields:headerDict];
}

/**
  Parses the JSON dictionary from the HTTP body of a request.

  @param request The request to parse the dictionary from.
  @returns The JSON dictionary or nil if parsing failed.
*/
- (NSDictionary *)dictFromRequest:(NSURLRequest *)request {
  NSData *bod = [request HTTPBody];
  if (bod) return [NSJSONSerialization JSONObjectWithData:bod options:0 error:NULL];
  return nil;
}

/**
  Generate a JSON data body from a dictionary

  @param dict, The dictionary of values
  @return A JSON-encoded representation of the dictionary as NSData
*/
- (NSData *)dataFromDict:(NSDictionary *)dict {
  return [NSJSONSerialization dataWithJSONObject:dict options:0 error:NULL];
}

/**
  Return data from a file in the Resources folder of the test bundle.

  @param file, The name of the file.
  @returns The contents of the named file, or nil.
*/
- (NSData *)dataFromFixture:(NSString *)file {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:file ofType:nil];
  XCTAssertNotNil(path, @"failed to load testdata: %@", file);
  return [NSData dataWithContentsOfFile:path];
}

- (void)setupDefaultDaemonConnResponses {
  struct RuleCounts ruleCounts = {0};
  OCMStub([self.daemonConnRop
    databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(ruleCounts), nil])]);
  OCMStub([self.daemonConnRop
    syncTypeRequired:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTSyncTypeNormal), nil])]);
  OCMStub([self.daemonConnRop
    clientMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTClientModeMonitor), nil])]);
}

#pragma mark - SNTSyncStage Tests

- (void)testStripXssi {
  SNTSyncStage *sut = [[SNTSyncStage alloc] initWithState:self.syncState];

  char wantChar[3] = {'"', 'a', '"'};
  NSData *want = [NSData dataWithBytes:wantChar length:3];

  char dOne[8] = {')', ']', '}', '\'', '\n', '"', 'a', '"'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dOne length:8]], want, @"");

  char dTwo[6] = {']', ')', '}', '"', 'a', '"'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dTwo length:6]], want, @"");

  char dThree[5] = {')', ']', '}', '\'', '\n'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dThree length:5]], [NSData data], @"");

  char dFour[3] = {']', ')', '}'};
  XCTAssertEqualObjects([sut stripXssi:[NSData dataWithBytes:dFour length:3]], [NSData data], @"");

  XCTAssertEqualObjects([sut stripXssi:want], want, @"");
}

- (void)testBaseFetchXSRFTokenSuccess {
  // NOTE: This test only works if the other tests don't return a 403 and run before this test.
  // The XSRF fetching code is inside a dispatch_once.

  // Stub initial failing request
  NSURLResponse *resp = [self responseWithCode:403 headerDict:nil];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    ![req valueForHTTPHeaderField:@"X-XSRF-TOKEN"]);
          }];

  // Stub XSRF token request
  resp = [self responseWithCode:200 headerDict:@{@"X-XSRF-TOKEN" : @"my-xsrf-token"}];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return [req.URL.absoluteString containsString:@"/xsrf/"];
          }];

  // Stub succeeding request
  [self
    stubRequestBody:nil
           response:nil
              error:nil
      validateBlock:^BOOL(NSURLRequest *req) {
        return ([req.URL.absoluteString containsString:@"/a/"] &&
                [[req valueForHTTPHeaderField:@"X-XSRF-TOKEN"] isEqualToString:@"my-xsrf-token"]);
      }];

  NSString *stageName = [@"a" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  NSURL *u1 = [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];

  SNTSyncStage *sut = [[SNTSyncStage alloc] initWithState:self.syncState];
  NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u1];
  XCTAssertTrue([sut performRequest:req]);
  XCTAssertEqualObjects(self.syncState.xsrfToken, @"my-xsrf-token");
}

- (void)testBaseFetchXSRFTokenHeaderRedirect {
  // Stub initial failing request
  NSURLResponse *resp = [self responseWithCode:403 headerDict:nil];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    ![req valueForHTTPHeaderField:@"X-Client-Xsrf-Token"]);
          }];

  // Stub XSRF token request
  resp = [self responseWithCode:200
                     headerDict:@{
                       @"X-XSRF-TOKEN" : @"my-xsrf-token",
                       @"X-XSRF-TOKEN-HEADER" : @"X-Client-Xsrf-Token",
                     }];
  [self stubRequestBody:nil
               response:resp
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return [req.URL.absoluteString containsString:@"/xsrf/"];
          }];

  // Stub succeeding request
  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    [[req valueForHTTPHeaderField:@"X-CLIENT-XSRF-TOKEN"]
                      isEqualToString:@"my-xsrf-token"]);
          }];

  NSString *stageName = [@"a" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  NSURL *u1 = [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];

  SNTSyncStage *sut = [[SNTSyncStage alloc] initWithState:self.syncState];
  NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u1];
  XCTAssertTrue([sut performRequest:req]);
  XCTAssertEqualObjects(self.syncState.xsrfToken, @"my-xsrf-token");
}

#pragma mark - SNTSyncPreflight Tests

- (void)testPreflightBasicResponse {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_basic.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqual(self.syncState.clientMode, SNTClientModeMonitor);
  XCTAssertEqual(self.syncState.eventBatchSize, 100);
  XCTAssertNil(self.syncState.allowlistRegex);
  XCTAssertNil(self.syncState.blocklistRegex);
  XCTAssertNil(self.syncState.overrideFileAccessAction);
}

- (void)testPreflightTurnOnBlockUSBMount {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_turn_on_blockusb.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqualObjects(self.syncState.blockUSBMount, @1);
  NSArray<NSString *> *wantRemountUSBMode = @[ @"rdonly", @"noexec" ];
  XCTAssertEqualObjects(self.syncState.remountUSBMode, wantRemountUSBMode);
}

- (void)testPreflightTurnOffBlockUSBMount {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_turn_off_blockusb.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqualObjects(self.syncState.blockUSBMount, @0);
}

- (void)testPreflightBlockUSBMountAbsent {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_blockusb_absent.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertNil(self.syncState.blockUSBMount);
}

- (void)testPreflightOverrideFileAccessAction {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [@"{\"override_file_access_action\": \"AuditOnly\", \"client_mode\": "
                      @"\"LOCKDOWN\", \"batch_size\": 100}" dataUsingEncoding:NSUTF8StringEncoding];

  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqualObjects(self.syncState.overrideFileAccessAction, @"AuditOnly");
}

- (void)testPreflightOverrideFileAccessActionAbsent {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [@"{\"client_mode\": \"LOCKDOWN\", \"batch_size\": 100}"
    dataUsingEncoding:NSUTF8StringEncoding];

  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertNil(self.syncState.overrideFileAccessAction);
}

- (void)testPreflightDatabaseCounts {
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  struct RuleCounts ruleCounts = {
    .binary = 5,
    .certificate = 8,
    .compiler = 2,
    .transitive = 19,
    .teamID = 3,
    .signingID = 123,
  };

  OCMStub([self.daemonConnRop
    databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(ruleCounts), nil])]);

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            XCTAssertEqualObjects(requestDict[kBinaryRuleCount], @(ruleCounts.binary));
            XCTAssertEqualObjects(requestDict[kCertificateRuleCount], @(ruleCounts.certificate));
            XCTAssertEqualObjects(requestDict[kCompilerRuleCount], @(ruleCounts.compiler));
            XCTAssertEqualObjects(requestDict[kTransitiveRuleCount], @(ruleCounts.transitive));
            XCTAssertEqualObjects(requestDict[kTeamIDRuleCount], @(ruleCounts.teamID));
            XCTAssertEqualObjects(requestDict[kSigningIDRuleCount], @(ruleCounts.signingID));
            return YES;
          }];

  [sut sync];
}

// This method is designed to help facilitate easy testing of many different
// permutations of clean sync request / response values and how syncType gets set.
- (void)cleanSyncPreflightRequiredSyncType:(SNTSyncType)requestedSyncType
                    expectcleanSyncRequest:(BOOL)expectcleanSyncRequest
                          expectedSyncType:(SNTSyncType)expectedSyncType
                                  response:(NSDictionary *)resp {
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  struct RuleCounts ruleCounts = {0};
  OCMStub([self.daemonConnRop
    databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(ruleCounts), nil])]);
  OCMStub([self.daemonConnRop
    clientMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTClientModeMonitor), nil])]);
  OCMStub([self.daemonConnRop
    syncTypeRequired:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(requestedSyncType), nil])]);

  NSData *respData = [self dataFromDict:resp];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            if (expectcleanSyncRequest) {
              XCTAssertEqualObjects(requestDict[kRequestCleanSync], @YES);
            } else {
              XCTAssertNil(requestDict[kRequestCleanSync]);
            }
            return YES;
          }];

  [sut sync];

  XCTAssertEqual(self.syncState.syncType, expectedSyncType);
}

- (void)testPreflightStateNormalRequestEmptyResponseEmpty {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{}];
}

- (void)testPreflightStateNormalRequestEmptyResponseNormal {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseClean {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kSyncType : @"clean"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseCleanAll {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean_all"}];
}

- (void)testPreflightStateNormalRequestEmptyResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeNormal
                    expectcleanSyncRequest:NO
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightStateCleanRequestCleanResponseEmpty {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{}];
}

- (void)testPreflightStateCleanRequestCleanResponseNormal {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal"}];
}

- (void)testPreflightStateCleanRequestCleanResponseClean {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kSyncType : @"clean"}];
}

- (void)testPreflightStateCleanRequestCleanResponseCleanAll {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean_all"}];
}

- (void)testPreflightStateCleanRequestCleanResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeClean
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeClean
                                  response:@{kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseEmpty {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseNormal {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseClean {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseCleanAll {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kSyncType : @"clean_all"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseCleanDep {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeCleanAll
                                  response:@{kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseUnknown {
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"foo"}];
}

- (void)testPreflightStateCleanAllRequestCleanResponseTypeAndDepMismatch {
  // Note: The kSyncType key takes precedence over kCleanSyncDeprecated if both are set
  [self cleanSyncPreflightRequiredSyncType:SNTSyncTypeCleanAll
                    expectcleanSyncRequest:YES
                          expectedSyncType:SNTSyncTypeNormal
                                  response:@{kSyncType : @"normal", kCleanSyncDeprecated : @YES}];
}

- (void)testPreflightLockdown {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_lockdown.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  [sut sync];

  XCTAssertEqual(self.syncState.clientMode, SNTClientModeLockdown);
}

#pragma mark - SNTSyncEventUpload Tests

- (void)testEventUploadBasic {
  SNTSyncEventUpload *sut = [[SNTSyncEventUpload alloc] initWithState:self.syncState];
  self.syncState.eventBatchSize = 50;

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_basic.plist"];
  NSArray *events = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];

  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  [self
    stubRequestBody:nil
           response:nil
              error:nil
      validateBlock:^BOOL(NSURLRequest *req) {
        NSDictionary *requestDict = [self dictFromRequest:req];
        NSArray *events = requestDict[kEvents];

        XCTAssertEqual(events.count, 2);

        NSDictionary *event = events[0];
        XCTAssertEqualObjects(event[kFileSHA256],
                              @"ff98fa0c0a1095fedcbe4d388a9760e71399a5c3c017a847ffa545663b57929a");
        XCTAssertEqualObjects(event[kFileName], @"yes");
        XCTAssertEqualObjects(event[kFilePath], @"/usr/bin");
        XCTAssertEqualObjects(event[kDecision], @"BLOCK_BINARY");
        NSArray *sessions = @[ @"foouser@console", @"foouser@ttys000" ];
        XCTAssertEqualObjects(event[kCurrentSessions], sessions);
        NSArray *users = @[ @"foouser" ];
        XCTAssertEqualObjects(event[kLoggedInUsers], users);
        XCTAssertEqualObjects(event[kExecutingUser], @"root");
        XCTAssertEqualObjects(event[kPID], @(11196));
        XCTAssertEqualObjects(event[kPPID], @(10760));
        XCTAssertEqualObjects(event[kExecutionTime], @(1464201698.537635));

        NSArray *certs = event[kSigningChain];
        XCTAssertEqual(certs.count, 3);

        NSDictionary *cert = [certs firstObject];
        XCTAssertEqualObjects(cert[kCertSHA256],
                              @"2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32");
        XCTAssertEqualObjects(cert[kCertCN], @"Software Signing");
        XCTAssertEqualObjects(cert[kCertOrg], @"Apple Inc.");
        XCTAssertEqualObjects(cert[kCertOU], @"Apple Software");
        XCTAssertEqualObjects(cert[kCertValidFrom], @(1365806075));
        XCTAssertEqualObjects(cert[kCertValidUntil], @(1618266875));

        XCTAssertEqualObjects(event[kTeamID], @"012345678910");
        XCTAssertEqualObjects(event[kSigningID], @"signing.id");

        event = events[1];
        XCTAssertEqualObjects(event[kFileName], @"hub");
        XCTAssertEqualObjects(event[kExecutingUser], @"foouser");
        certs = event[kSigningChain];
        XCTAssertEqual(certs.count, 0);

        return YES;
      }];

  [sut sync];
}

- (void)testEventUploadBundleAndQuarantineData {
  SNTSyncEventUpload *sut = [[SNTSyncEventUpload alloc] initWithState:self.syncState];
  sut = OCMPartialMock(sut);

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_quarantine.plist"];
  NSArray *events = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];
  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            NSArray *events = requestDict[kEvents];

            XCTAssertEqual(events.count, 1);

            NSDictionary *event = [events firstObject];
            XCTAssertEqualObjects(event[kFileBundleID], @"com.luckymarmot.Paw");
            XCTAssertEqualObjects(event[kFileBundlePath], @"/Applications/Paw.app");
            XCTAssertEqualObjects(event[kFileBundleVersion], @"2003004001");
            XCTAssertEqualObjects(event[kFileBundleShortVersionString], @"2.3.4");
            XCTAssertEqualObjects(event[kQuarantineTimestamp], @(1464204868));
            XCTAssertEqualObjects(event[kQuarantineAgentBundleID], @"com.google.Chrome");
            XCTAssertEqualObjects(
              event[kQuarantineDataURL],
              @"https://d3hevc2w7wq7nj.cloudfront.net/paw/Paw-2.3.4-2003004001.zip");
            XCTAssertEqualObjects(event[kQuarantineRefererURL], @"https://luckymarmot.com/paw");

            return YES;
          }];

  [sut sync];
}

- (void)testEventUploadBatching {
  SNTSyncEventUpload *sut = [[SNTSyncEventUpload alloc] initWithState:self.syncState];
  self.syncState.eventBatchSize = 1;
  sut = OCMPartialMock(sut);

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_basic.plist"];
  NSArray *events = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];
  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  __block int requestCount = 0;

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            requestCount++;
            return YES;
          }];

  [sut sync];

  XCTAssertEqual(requestCount, 2);
}

#pragma mark - SNTSyncRuleDownload Tests

- (void)testRuleDownload {
  SNTSyncRuleDownload *sut = [[SNTSyncRuleDownload alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_ruledownload_batch1.json"];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            return requestDict[@"cursor"] == nil;
          }];

  respData = [self dataFromFixture:@"sync_ruledownload_batch2.json"];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            return requestDict[@"cursor"] != nil;
          }];

  // Stub out the call to invoke the block, verification of the input is later
  OCMStub([self.daemonConnRop
    databaseRuleAddRules:OCMOCK_ANY
             ruleCleanup:SNTRuleCleanupNone
                   reply:([OCMArg invokeBlockWithArgs:[NSNull null], nil])]);
  [sut sync];

  NSArray *rules = @[
    [[SNTRule alloc]
      initWithIdentifier:@"ee382e199f7eda58863a93a7854b930ade35798bc6856ee8e6ab6ce9277f0eab"
                   state:SNTRuleStateBlock
                    type:SNTRuleTypeBinary
               customMsg:@""],
    [[SNTRule alloc]
      initWithIdentifier:@"46f8c706d0533a54554af5fc163eea704f10c08b30f8a5db12bfdc04fb382fc3"
                   state:SNTRuleStateAllow
                    type:SNTRuleTypeCertificate
               customMsg:@""],
    [[SNTRule alloc]
      initWithIdentifier:@"7846698e47ef41be80b83fb9e2b98fa6dc46c9188b068bff323c302955a00142"
                   state:SNTRuleStateBlock
                    type:SNTRuleTypeCertificate
               customMsg:@"Hi There"],
    [[SNTRule alloc] initWithIdentifier:@"AAAAAAAAAA"
                                  state:SNTRuleStateBlock
                                   type:SNTRuleTypeTeamID
                              customMsg:@"Banned team ID"],
  ];

  OCMVerify([self.daemonConnRop databaseRuleAddRules:rules
                                         ruleCleanup:SNTRuleCleanupNone
                                               reply:OCMOCK_ANY]);
}

#pragma mark - SNTSyncPostflight Tests

- (void)testPostflightBasicResponse {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPostflight *sut = [[SNTSyncPostflight alloc] initWithState:self.syncState];

  [self stubRequestBody:nil response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setFullSyncLastSuccess:OCMOCK_ANY reply:OCMOCK_ANY]);

  self.syncState.clientMode = SNTClientModeMonitor;
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setClientMode:SNTClientModeMonitor reply:OCMOCK_ANY]);

  // For Clean syncs, the sync type required should be reset to normal
  self.syncState.syncType = SNTSyncTypeClean;
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setSyncTypeRequired:SNTSyncTypeNormal reply:OCMOCK_ANY]);

  // For Clean All syncs, the sync type required should be reset to normal
  self.syncState.syncType = SNTSyncTypeCleanAll;
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setSyncTypeRequired:SNTSyncTypeNormal reply:OCMOCK_ANY]);

  self.syncState.allowlistRegex = @"^horse$";
  self.syncState.blocklistRegex = @"^donkey$";
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setAllowedPathRegex:@"^horse$" reply:OCMOCK_ANY]);
  OCMVerify([self.daemonConnRop setBlockedPathRegex:@"^donkey$" reply:OCMOCK_ANY]);

  self.syncState.blockUSBMount = @1;
  self.syncState.remountUSBMode = @[ @"readonly" ];
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setBlockUSBMount:YES reply:OCMOCK_ANY]);
  OCMVerify([self.daemonConnRop setRemountUSBMode:@[ @"readonly" ] reply:OCMOCK_ANY]);

  self.syncState.blockUSBMount = @0;
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setBlockUSBMount:NO reply:OCMOCK_ANY]);

  self.syncState.overrideFileAccessAction = @"Disable";
  XCTAssertTrue([sut sync]);
  OCMVerify([self.daemonConnRop setOverrideFileAccessAction:@"Disable" reply:OCMOCK_ANY]);
}

@end
