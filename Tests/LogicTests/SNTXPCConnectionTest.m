/// Copyright 2015 Google Inc. All rights reserved.
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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "MOLCodesignChecker.h"
#import "SNTXPCConnection.h"

@protocol XPCConnectionValidityRequest
- (void)isConnectionValidWithBlock:(void (^)(BOOL))block;
@end

@interface SNTXPCConnectionTest : XCTestCase
@property id mockListener;
@property id mockConnection;
@end

@implementation SNTXPCConnectionTest

- (void)setUp {
  [super setUp];
  self.mockListener = OCMClassMock([NSXPCListener class]);
  OCMStub([self.mockListener alloc]).andReturn(self.mockListener);

  self.mockConnection = OCMClassMock([NSXPCConnection class]);
  OCMStub([self.mockConnection alloc]).andReturn(self.mockConnection);
}

- (void)tearDown {
  [super tearDown];
}

- (void)testPlainInit {
  XCTAssertThrows([[SNTXPCConnection alloc] init]);
}

- (void)testInitClient {
  OCMExpect([self.mockConnection initWithMachServiceName:@"TestClient"
                                                 options:NSXPCConnectionPrivileged])
      .andReturn(self.mockConnection);

  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initClientWithName:@"TestClient"
                                                            privileged:YES];
  XCTAssertNotNil(sut);
  OCMVerifyAll(self.mockConnection);
}

- (void)testInitServer {
  OCMExpect([self.mockListener initWithMachServiceName:@"TestServer"]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];
  XCTAssertNotNil(sut);
  OCMVerifyAll(self.mockListener);
}

- (void)testResume {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [sut resume];

  OCMVerify([(NSXPCListener *)self.mockListener setDelegate:sut]);
  OCMVerify([(NSXPCListener *)self.mockListener resume]);
}

- (void)testServerNotValid {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  id mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([mockCodesignChecker alloc]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker initWithPID:0]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker signingInformationMatches:OCMOCK_ANY]).andReturn(NO);

  XCTAssertFalse([sut listener:self.mockListener shouldAcceptNewConnection:self.mockConnection]);

  [mockCodesignChecker stopMocking];
}

- (void)testServerValid {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  id mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([mockCodesignChecker alloc]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker initWithPID:0]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker signingInformationMatches:OCMOCK_ANY]).andReturn(YES);

  XCTAssertTrue([sut listener:self.mockListener shouldAcceptNewConnection:self.mockConnection]);

  [mockCodesignChecker stopMocking];
}

- (void)testServerInvalidateAllConnections {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  int pid = [[NSProcessInfo processInfo] processIdentifier];

  NSMutableArray *connections = [NSMutableArray array];
  for (int i = 0; i < 10; ++i) {
    NSXPCConnection *fakeConn = OCMClassMock([NSXPCConnection class]);
    OCMStub([fakeConn processIdentifier]).andReturn(pid);
    OCMExpect([fakeConn invalidate]);
    [connections addObject:fakeConn];
    [sut listener:self.mockListener shouldAcceptNewConnection:fakeConn];
  }

  [sut invalidate];

  for (NSXPCConnection *fakeConn in connections) {
    OCMVerifyAll((OCMockObject *)fakeConn);
  }
}

@end
