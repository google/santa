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

#import "SNTCodesignChecker.h"
#import "SNTXPCConnection.h"

@interface SNTXPCConnection (Testing)
- (void)isConnectionValidWithBlock:(void (^)(BOOL))block;
- (void)invokeAcceptedHandler;
- (void)invokeRejectedHandler;
- (void)invokeInvalidationHandler;
@property NSXPCConnection *currentConnection;
@property NSXPCInterface *validatorInterface;
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
                                                               options:NSXPCConnectionPrivileged];
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

- (void)testListenerShouldAcceptNewConnection {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  XCTAssertTrue([sut listener:self.mockListener shouldAcceptNewConnection:self.mockConnection]);

  OCMVerify([self.mockConnection setExportedObject:sut]);
  OCMVerify([self.mockConnection setExportedInterface:OCMOCK_ANY]);
  OCMVerify([self.mockConnection setInvalidationHandler:OCMOCK_ANY]);
  OCMVerify([self.mockConnection setInterruptionHandler:OCMOCK_ANY]);
  OCMVerify([(NSXPCConnection *)self.mockConnection resume]);
}

- (void)testIsConnectionValidFalse {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [sut setCurrentConnection:self.mockConnection];

  OCMExpect([self.mockConnection processIdentifier]).andReturn(1);

  id mockCodesignChecker = OCMClassMock([SNTCodesignChecker class]);
  OCMExpect([mockCodesignChecker alloc]).andReturn(mockCodesignChecker);
  OCMExpect([mockCodesignChecker signingInformationMatches:OCMOCK_ANY]).andReturn(NO);

  [sut isConnectionValidWithBlock:^(BOOL input) {
      XCTAssertFalse(input);
  }];

  XCTAssertNil(sut.currentConnection);

  OCMVerify([self.mockConnection invalidate]);
  [mockCodesignChecker stopMocking];
}

- (void)testIsConnectionValidTrue {
  OCMExpect([self.mockListener initWithMachServiceName:OCMOCK_ANY]).andReturn(self.mockListener);
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [sut setCurrentConnection:self.mockConnection];

  pid_t mypid = [[NSProcessInfo processInfo] processIdentifier];
  OCMExpect([self.mockConnection processIdentifier]).andReturn(mypid);

  [sut isConnectionValidWithBlock:^(BOOL input) {
    XCTAssertTrue(input);
  }];

  OCMVerify([(NSXPCConnection *)self.mockConnection suspend]);
  OCMVerify([self.mockConnection setRemoteObjectInterface:OCMOCK_ANY]);
  OCMVerify([self.mockConnection setExportedInterface:OCMOCK_ANY]);
  OCMVerify([self.mockConnection setExportedObject:OCMOCK_ANY]);
  OCMVerify([(NSXPCConnection *)self.mockConnection resume]);
}

@end
