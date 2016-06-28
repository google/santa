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

#import <OCMock/OCMock.h>

#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncEventUpload.h"
#import "SNTCommandSyncPostflight.h"
#import "SNTCommandSyncPreflight.h"
#import "SNTCommandSyncRuleDownload.h"
#import "SNTCommandSyncState.h"
#import "SNTCommandSyncStage.h"
#import "SNTCommonEnums.h"
#import "SNTRule.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

// Prevent Zlib compression during testing
@implementation NSData (Zlib)
- (NSData *)zlibCompressed {
  return nil;
}
- (NSData *)gzipCompressed {
  return nil;
}
@end

@interface SNTCommandSyncEventUpload (Testing)
- (NSArray *)findRelatedBinaries:(SNTStoredEvent *)event;
@end

@interface SNTCommandSyncTest : XCTestCase
@property SNTCommandSyncState *syncState;
@property id<SNTDaemonControlXPC> daemonConnRop;
@end

@implementation SNTCommandSyncTest

- (void)setUp {
  [super setUp];

  self.syncState = [[SNTCommandSyncState alloc] init];
  self.syncState.daemonConn = OCMClassMock([SNTXPCConnection class]);
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
          validateBlock:(BOOL(^)(NSURLRequest *req))validateBlock {
  if (!respData) respData = (NSData *)[NSNull null];
  if (!resp) resp = [self responseWithCode:200 headerDict:nil];
  if (!err) err = (NSError *)[NSNull null];

  // Cast the value into an NSURLRequest to save callers doing it.
  BOOL (^validateBlockWrapper)(id value) = ^BOOL(id value) {
    if (!validateBlock) return YES;
    NSURLRequest *req = (NSURLRequest *)value;
    return validateBlock(req);
  };

  OCMStub([self.syncState.session dataTaskWithRequest:[OCMArg checkWithBlock:validateBlockWrapper]
                                    completionHandler:([OCMArg invokeBlockWithArgs:respData,
                                                           resp, err, nil])]);
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
  return [NSData dataWithContentsOfFile:path];
}

#pragma mark - SNTCommandSyncStage Tests

- (void)testBaseFetchXSRFTokenSuccess {
  // NOTE: This test only works if the other tests don't return a 403 and run before this test.
  // The XSRF fetching code is inside a dispatch_once.

  // Stub initial failing request
  NSURLResponse *resp = [self responseWithCode:403 headerDict:nil];
  [self stubRequestBody:nil response:resp error:nil validateBlock:^BOOL(NSURLRequest *req) {
    return ([req.URL.absoluteString containsString:@"/a/"] &&
            ![req valueForHTTPHeaderField:@"X-XSRF-TOKEN"]);
  }];

  // Stub XSRF token request
  resp = [self responseWithCode:200 headerDict:@{ @"X-XSRF-TOKEN": @"my-xsrf-token" }];
  [self stubRequestBody:nil response:resp error:nil validateBlock:^BOOL(NSURLRequest *req) {
    return [req.URL.absoluteString containsString:@"/xsrf/"];
  }];

  // Stub succeeding request
  [self stubRequestBody:nil response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    return ([req.URL.absoluteString containsString:@"/a/"] &&
            [[req valueForHTTPHeaderField:@"X-XSRF-TOKEN"] isEqual:@"my-xsrf-token"]);
  }];

  NSString *stageName = [@"a" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  NSURL *u1 = [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];

  SNTCommandSyncStage *sut = [[SNTCommandSyncStage alloc] initWithState:self.syncState];
  NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u1];
  XCTAssertTrue([sut performRequest:req]);
  XCTAssertEqualObjects(self.syncState.xsrfToken, @"my-xsrf-token");
}

#pragma mark - SNTCommandSyncPreflight Tests

- (void)testPreflightBasicResponse {
  SNTCommandSyncPreflight *sut = [[SNTCommandSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_basic.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  XCTAssertTrue([sut sync]);
  XCTAssertEqual(self.syncState.clientMode, SNTClientModeMonitor);
  XCTAssertEqual(self.syncState.eventBatchSize, 100);
  XCTAssertNil(self.syncState.whitelistRegex);
  XCTAssertNil(self.syncState.blacklistRegex);
}

- (void)testPreflightDatabaseCounts {
  SNTCommandSyncPreflight *sut = [[SNTCommandSyncPreflight alloc] initWithState:self.syncState];

  int64_t bin = 5, cert = 8;
  OCMStub([self.daemonConnRop databaseRuleCounts:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(bin),
                                                                              OCMOCK_VALUE(cert),
                                                                              nil])]);

  [self stubRequestBody:nil response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    NSDictionary *requestDict = [self dictFromRequest:req];
    XCTAssertEqualObjects(requestDict[kBinaryRuleCount], @(5));
    XCTAssertEqualObjects(requestDict[kCertificateRuleCount], @(8));
    return YES;
  }];

  [sut sync];
}

- (void)testPreflightCleanSync {
  SNTCommandSyncPreflight *sut = [[SNTCommandSyncPreflight alloc] initWithState:self.syncState];

  id processInfoMock = OCMClassMock([NSProcessInfo class]);
  OCMStub([processInfoMock processInfo]).andReturn(processInfoMock);
  [OCMStub([processInfoMock arguments]) andReturn:@[ @"xctest", @"--clean" ]];

  NSData *respData = [self dataFromDict:@{ kCleanSync: @YES }];
  [self stubRequestBody:respData response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    NSDictionary *requestDict = [self dictFromRequest:req];
    XCTAssertEqualObjects(requestDict[kRequestCleanSync], @YES);
    return YES;
  }];

  [sut sync];

  XCTAssertEqual(self.syncState.cleanSync, YES);
}

- (void)testPreflightLockdown {
  SNTCommandSyncPreflight *sut = [[SNTCommandSyncPreflight alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_preflight_lockdown.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:nil];

  [sut sync];

  XCTAssertEqual(self.syncState.clientMode, SNTClientModeLockdown);
}

#pragma mark - SNTCommandSyncEventUpload Tests

- (void)testEventUploadBasic {
  SNTCommandSyncEventUpload *sut = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  self.syncState.eventBatchSize = 50;

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_basic.plist"];
  NSArray *events = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];

  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  [self stubRequestBody:nil response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    NSDictionary *requestDict = [self dictFromRequest:req];
    NSArray *events = requestDict[@"events"];

    XCTAssertEqual(events.count, 2);

    NSDictionary *event = events[0];
    XCTAssertEqualObjects(event[@"file_sha256"],
                          @"ff98fa0c0a1095fedcbe4d388a9760e71399a5c3c017a847ffa545663b57929a");
    XCTAssertEqualObjects(event[@"file_name"], @"yes");
    XCTAssertEqualObjects(event[@"file_path"], @"/usr/bin");
    XCTAssertEqualObjects(event[@"decision"], @"BLOCK_BINARY");
    NSArray *sessions = @[ @"foouser@console", @"foouser@ttys000"];
    XCTAssertEqualObjects(event[@"current_sessions"], sessions);
    NSArray *users = @[ @"foouser" ];
    XCTAssertEqualObjects(event[@"logged_in_users"], users);
    XCTAssertEqualObjects(event[@"executing_user"], @"root");
    XCTAssertEqualObjects(event[@"pid"], @(11196));
    XCTAssertEqualObjects(event[@"ppid"], @(10760));
    XCTAssertEqualObjects(event[@"execution_time"], @(1464201698.537635));

    NSArray *certs = event[@"signing_chain"];
    XCTAssertEqual(certs.count, 3);

    NSDictionary *cert = [certs firstObject];
    XCTAssertEqualObjects(cert[@"sha256"],
                          @"2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32");
    XCTAssertEqualObjects(cert[@"cn"], @"Software Signing");
    XCTAssertEqualObjects(cert[@"org"], @"Apple Inc.");
    XCTAssertEqualObjects(cert[@"ou"], @"Apple Software");
    XCTAssertEqualObjects(cert[@"valid_from"], @(1365806075));
    XCTAssertEqualObjects(cert[@"valid_until"], @(1618266875));

    event = events[1];
    XCTAssertEqualObjects(event[@"file_name"], @"hub");
    XCTAssertEqualObjects(event[@"executing_user"], @"foouser");
    certs = event[@"signing_chain"];
    XCTAssertEqual(certs.count, 0);

    return YES;
  }];

  [sut sync];
}

- (void)testEventUploadBundleAndQuarantineData {
  SNTCommandSyncEventUpload *sut = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  sut = OCMPartialMock(sut);
  OCMStub([sut findRelatedBinaries:OCMOCK_ANY]);

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_quarantine.plist"];
  NSArray *events = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];
  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  [self stubRequestBody:nil response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    NSDictionary *requestDict = [self dictFromRequest:req];
    NSArray *events = requestDict[@"events"];

    XCTAssertEqual(events.count, 1);

    NSDictionary *event = [events firstObject];
    XCTAssertEqualObjects(event[@"file_bundle_id"], @"com.luckymarmot.Paw");
    XCTAssertEqualObjects(event[@"file_bundle_path"], @"/Applications/Paw.app");
    XCTAssertEqualObjects(event[@"file_bundle_version"], @"2003004001");
    XCTAssertEqualObjects(event[@"file_bundle_version_string"], @"2.3.4");
    XCTAssertEqualObjects(event[@"quarantine_timestamp"], @(1464204868));
    XCTAssertEqualObjects(event[@"quarantine_agent_bundle_id"], @"com.google.Chrome");
    XCTAssertEqualObjects(event[@"quarantine_data_url"],
                          @"https://d3hevc2w7wq7nj.cloudfront.net/paw/Paw-2.3.4-2003004001.zip");
    XCTAssertEqualObjects(event[@"quarantine_referer_url"], @"https://luckymarmot.com/paw");

    return YES;
  }];
  
  [sut sync];
}

- (void)testEventUploadBatching {
  SNTCommandSyncEventUpload *sut = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  self.syncState.eventBatchSize = 1;
  sut = OCMPartialMock(sut);
  OCMStub([sut findRelatedBinaries:OCMOCK_ANY]);

  NSData *eventData = [self dataFromFixture:@"sync_eventupload_input_basic.plist"];
  NSArray *events = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];
  OCMStub([self.daemonConnRop databaseEventsPending:([OCMArg invokeBlockWithArgs:events, nil])]);

  __block int requestCount = 0;

  [self stubRequestBody:nil response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    requestCount++;
    return YES;
  }];

  [sut sync];

  XCTAssertEqual(requestCount, 2);
}

#pragma mark - SNTCommandSyncRuleDownload Tests

- (void)testRuleDownload {
  SNTCommandSyncRuleDownload *sut =
      [[SNTCommandSyncRuleDownload alloc] initWithState:self.syncState];

  NSData *respData = [self dataFromFixture:@"sync_ruledownload_batch1.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    NSDictionary *requestDict = [self dictFromRequest:req];
    return requestDict[@"cursor"] == nil;
  }];

  respData = [self dataFromFixture:@"sync_ruledownload_batch2.json"];
  [self stubRequestBody:respData response:nil error:nil validateBlock:^BOOL(NSURLRequest *req) {
    NSDictionary *requestDict = [self dictFromRequest:req];
    return requestDict[@"cursor"] != nil;
  }];

  // Stub out the call to invoke the block, verification of the input is later
  OCMStub([self.daemonConnRop databaseRuleAddRules:OCMOCK_ANY
                                        cleanSlate:NO
                                             reply:([OCMArg invokeBlockWithArgs:[NSNull null], nil])]);
  [sut sync];

  NSArray *rules = @[
    [[SNTRule alloc] initWithShasum:@"ee382e199f7eda58863a93a7854b930ade35798bc6856ee8e6ab6ce9277f0eab"
                              state:SNTRuleStateBlacklist
                               type:SNTRuleTypeBinary
                          customMsg:@""],
    [[SNTRule alloc] initWithShasum:@"46f8c706d0533a54554af5fc163eea704f10c08b30f8a5db12bfdc04fb382fc3"
                              state:SNTRuleStateWhitelist
                               type:SNTRuleTypeCertificate
                          customMsg:@""],
    [[SNTRule alloc] initWithShasum:@"7846698e47ef41be80b83fb9e2b98fa6dc46c9188b068bff323c302955a00142"
                              state:SNTRuleStateBlacklist
                               type:SNTRuleTypeCertificate
                          customMsg:@"Hi There"],
  ];

  OCMVerify([self.daemonConnRop databaseRuleAddRules:rules cleanSlate:NO reply:OCMOCK_ANY]);
}

@end
