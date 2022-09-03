/// Copyright 2022 Google Inc. All rights reserved.
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
#include <dispatch/dispatch.h>

#include "Source/santad/EventProviders/EndpointSecurity/Client.h"

using santa::santad::event_providers::endpoint_security::Client;

// Global semaphore used for custom `es_delete_client` function
dispatch_semaphore_t gSema;

// Note: The Client class does not use the `EndpointSecurityAPI` wrappers due
// to circular dependency issues. It is a special case that uses the underlying
// ES API `es_delete_client` directly. This test override will signal the
// `gSema` semaphore to indicate it has been called.
es_return_t es_delete_client(es_client_t *_Nullable client) {
  dispatch_semaphore_signal(gSema);
  return ES_RETURN_SUCCESS;
};

@interface ClientTest : XCTestCase
@end

@implementation ClientTest

- (void)setUp {
  gSema = dispatch_semaphore_create(0);
}

- (void)testConstructorsAndDestructors {
  // Ensure constructors set internal state properly
  // Anonymous scopes used to ensure destructors called as expected

  // Null `es_client_t*` *shouldn't* trigger `es_delete_client`
  {
    auto c = Client();
    XCTAssertEqual(c.Get(), nullptr);
    XCTAssertEqual(c.NewClientResult(), ES_NEW_CLIENT_RESULT_ERR_INTERNAL);
  }

  XCTAssertNotEqual(0, dispatch_semaphore_wait(gSema, DISPATCH_TIME_NOW),
                    "es_delete_client called unexpectedly");

  // Nonnull `es_client_t*` *should* trigger `es_delete_client`
  {
    int fake;
    es_client_t *fake_client = (es_client_t *)&fake;
    auto c = Client(fake_client, ES_NEW_CLIENT_RESULT_SUCCESS);
    XCTAssertEqual(c.Get(), fake_client);
    XCTAssertEqual(c.NewClientResult(), ES_NEW_CLIENT_RESULT_SUCCESS);
  }

  XCTAssertEqual(0, dispatch_semaphore_wait(gSema, DISPATCH_TIME_NOW),
                 "es_delete_client not called within expected time window");

  // Test move constructor
  {
    int fake;
    es_client_t *fake_client = (es_client_t *)&fake;
    auto c1 = Client(fake_client, ES_NEW_CLIENT_RESULT_SUCCESS);

    Client c2(std::move(c1));

    XCTAssertEqual(c1.Get(), nullptr);
    XCTAssertEqual(c2.Get(), fake_client);
    XCTAssertEqual(c2.NewClientResult(), ES_NEW_CLIENT_RESULT_SUCCESS);
  }

  // Ensure `es_delete_client` was only called once when both `c1` and `c2`
  // are destructed.
  XCTAssertEqual(0, dispatch_semaphore_wait(gSema, DISPATCH_TIME_NOW),
                 "es_delete_client not called within expected time window");
  XCTAssertNotEqual(0, dispatch_semaphore_wait(gSema, DISPATCH_TIME_NOW),
                    "es_delete_client called unexpectedly");

  // Test move assignment
  {
    int fake;
    es_client_t *fake_client = (es_client_t *)&fake;
    auto c1 = Client(fake_client, ES_NEW_CLIENT_RESULT_SUCCESS);
    Client c2;

    c2 = std::move(c1);

    XCTAssertEqual(c1.Get(), nullptr);
    XCTAssertEqual(c2.Get(), fake_client);
    XCTAssertEqual(c2.NewClientResult(), ES_NEW_CLIENT_RESULT_SUCCESS);
  }

  // Ensure `es_delete_client` was only called once when both `c1` and `c2`
  // are destructed.
  XCTAssertEqual(0, dispatch_semaphore_wait(gSema, DISPATCH_TIME_NOW),
                 "es_delete_client not called within expected time window");
  XCTAssertNotEqual(0, dispatch_semaphore_wait(gSema, DISPATCH_TIME_NOW),
                    "es_delete_client called unexpectedly");
}

- (void)testIsConnected {
  XCTAssertFalse(Client().IsConnected());
  XCTAssertFalse(Client(nullptr, ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED).IsConnected());
  XCTAssertTrue(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS).IsConnected());
}

@end
