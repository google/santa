/// Copyright 2014 Google Inc. All rights reserved.
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
  self.mockListener = [OCMockObject niceMockForClass:[NSXPCListener class]];
  [[[self.mockListener stub] andReturn:self.mockListener] alloc];

  self.mockConnection = [OCMockObject niceMockForClass:[NSXPCConnection class]];
  [[[self.mockConnection stub] andReturn:self.mockConnection] alloc];
}

- (void)tearDown {
  [super tearDown];
}

- (void)testPlainInit {
  XCTAssertThrows([[SNTXPCConnection alloc] init]);
}

- (void)testInitClient {
  (void)[[[self.mockConnection stub] andReturn:self.mockConnection]
         initWithMachServiceName:@"TestClient" options:NSXPCConnectionPrivileged];

  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initClientWithName:@"TestClient"
                                                           options:NSXPCConnectionPrivileged];
  XCTAssertNotNil(sut);

  [self.mockConnection verify];
}

- (void)testInitServer {
  (void)[[[self.mockListener stub] andReturn:self.mockListener]
         initWithMachServiceName:@"TestServer"];

  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];
  XCTAssertNotNil(sut);

  [self.mockListener verify];
}


- (void)testResume {
  (void)[[[self.mockListener stub] andReturn:self.mockListener] initWithMachServiceName:OCMOCK_ANY];
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [(NSXPCListener *)[self.mockListener expect] setDelegate:sut];
  [(NSXPCListener *)[self.mockListener expect] resume];

  [sut resume];

  [self.mockListener verify];
}

- (void)testListenerShouldAcceptNewConnection {
  (void)[[[self.mockListener stub] andReturn:self.mockListener] initWithMachServiceName:OCMOCK_ANY];
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [[self.mockConnection expect] setExportedObject:sut];
  [[self.mockConnection expect] setExportedInterface:OCMOCK_ANY];
  [[self.mockConnection expect] setInvalidationHandler:OCMOCK_ANY];
  [[self.mockConnection expect] setInterruptionHandler:OCMOCK_ANY];
  [(NSXPCConnection *)[self.mockConnection expect] resume];

  XCTAssertTrue([sut listener:self.mockListener shouldAcceptNewConnection:self.mockConnection]);

  [self.mockConnection verify];
}

- (void)testIsConnectionValidFalse {
  (void)[[[self.mockListener stub] andReturn:self.mockListener] initWithMachServiceName:OCMOCK_ANY];
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [sut setCurrentConnection:self.mockConnection];

  [[[self.mockConnection stub] andReturnValue:@(1)] processIdentifier];
  [[self.mockConnection expect] invalidate];

  id mockCodesignChecker = [OCMockObject niceMockForClass:[SNTCodesignChecker class]];
  [[[mockCodesignChecker stub] andReturn:mockCodesignChecker] alloc];
  [[[mockCodesignChecker stub] andReturn:NO] signingInformationMatches:OCMOCK_ANY];

  [sut isConnectionValidWithBlock:^(BOOL input) {
      XCTAssertFalse(input);
  }];

  XCTAssertNil(sut.currentConnection);

  [self.mockConnection verify];

  [mockCodesignChecker stopMocking];
}

- (void)testIsConnectionValidTrue {
  (void)[[[self.mockListener stub] andReturn:self.mockListener] initWithMachServiceName:OCMOCK_ANY];
  SNTXPCConnection *sut = [[SNTXPCConnection alloc] initServerWithName:@"TestServer"];

  [sut setCurrentConnection:self.mockConnection];

  pid_t mypid = [[NSProcessInfo processInfo] processIdentifier];
  [[[self.mockConnection stub] andReturnValue:@(mypid)] processIdentifier];

  [(NSXPCConnection *)[self.mockConnection expect] suspend];
  [(NSXPCConnection *)[self.mockConnection expect] setRemoteObjectInterface:OCMOCK_ANY];
  [(NSXPCConnection *)[self.mockConnection expect] setExportedInterface:OCMOCK_ANY];
  [(NSXPCConnection *)[self.mockConnection expect] setExportedObject:OCMOCK_ANY];
  [(NSXPCConnection *)[self.mockConnection expect] resume];

  [sut isConnectionValidWithBlock:^(BOOL input) {
    XCTAssertTrue(input);
  }];

  [self.mockConnection verify];
}

@end