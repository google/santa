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

#import <XCTest/XCTest.h>

#import <MOLXPCConnection/MOLXPCConnection.h>
#import <OCMock/OCMock.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncConstants.h"
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
  OCMStub([self.daemonConnRop
    databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(0),  // binary
                                                    OCMOCK_VALUE(0),  // cert
                                                    OCMOCK_VALUE(0),  // compiler
                                                    OCMOCK_VALUE(0),  // transitive
                                                    OCMOCK_VALUE(0),  // teamID
                                                    nil])]);
  OCMStub([self.daemonConnRop syncCleanRequired:([OCMArg invokeBlockWithArgs:@NO, nil])]);
  OCMStub([self.daemonConnRop
    clientMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTClientModeMonitor), nil])]);
}

#pragma mark - SNTSyncStage Tests

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
  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            return ([req.URL.absoluteString containsString:@"/a/"] &&
                    [[req valueForHTTPHeaderField:@"X-XSRF-TOKEN"] isEqual:@"my-xsrf-token"]);
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
}

- (void)testPreflightBlockUSBMount {
  [self setupDefaultDaemonConnResponses];
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_toggle_blockusb.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqual(self.syncState.blockUSBMount, true);
  NSArray<NSString *> *wantRemountUSBMode = @[ @"rdonly", @"noexec" ];
  XCTAssertEqualObjects(self.syncState.remountUSBMode, wantRemountUSBMode);
}

- (void)testPreflightDatabaseCounts {
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  int64_t bin = 5, cert = 8, compiler = 2, transitive = 19, teamID = 3;
  OCMStub([self.daemonConnRop
    databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(bin), OCMOCK_VALUE(cert),
                                                    OCMOCK_VALUE(compiler),
                                                    OCMOCK_VALUE(transitive), OCMOCK_VALUE(teamID),
                                                    nil])]);

  [self stubRequestBody:nil
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            XCTAssertEqualObjects(requestDict[kBinaryRuleCount], @(5));
            XCTAssertEqualObjects(requestDict[kCertificateRuleCount], @(8));
            XCTAssertEqualObjects(requestDict[kCompilerRuleCount], @(2));
            XCTAssertEqualObjects(requestDict[kTransitiveRuleCount], @(19));
            XCTAssertEqualObjects(requestDict[kTeamIDRuleCount], @(3));
            return YES;
          }];

  [sut sync];
}

- (void)testPreflightCleanSync {
  SNTSyncPreflight *sut = [[SNTSyncPreflight alloc] initWithState:self.syncState];

  OCMStub([self.daemonConnRop
    databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(0),  // binary
                                                    OCMOCK_VALUE(0),  // cert
                                                    OCMOCK_VALUE(0),  // compiler
                                                    OCMOCK_VALUE(0),  // transitive
                                                    OCMOCK_VALUE(0),  // teamID
                                                    nil])]);
  OCMStub([self.daemonConnRop
    clientMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(SNTClientModeMonitor), nil])]);
  OCMStub([self.daemonConnRop syncCleanRequired:([OCMArg invokeBlockWithArgs:@YES, nil])]);

  NSData *respData = [self dataFromDict:@{kCleanSync : @YES}];
  [self stubRequestBody:respData
               response:nil
                  error:nil
          validateBlock:^BOOL(NSURLRequest *req) {
            NSDictionary *requestDict = [self dictFromRequest:req];
            XCTAssertEqualObjects(requestDict[kRequestCleanSync], @YES);
            return YES;
          }];

  [sut sync];

  XCTAssertEqual(self.syncState.cleanSync, YES);
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

        XCTAssertNil(event[kTeamID]);

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
              cleanSlate:NO
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

  OCMVerify([self.daemonConnRop databaseRuleAddRules:rules cleanSlate:NO reply:OCMOCK_ANY]);
}

@end
