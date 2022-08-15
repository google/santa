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

#include <dispatch/dispatch.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include "Source/santad/EventProviders/EndpointSecurity/Client.h"

using santa::santad::event_providers::endpoint_security::Client;

// Global semaphore used for custom `es_delete_client` function
dispatch_semaphore_t gDeleteClientSema;

// Note: The Client class does not use the `EndpointSecurityAPI` wrappers due
// to circular dependency issues. It is a special case that uses the underlying
// ES API `es_delete_client` directly. This test override will signal the
// `gDeleteClientSema` semaphore to indicate it has been called.
es_return_t es_delete_client(
    es_client_t *_Nullable client) {
  dispatch_semaphore_signal(gDeleteClientSema);
  return ES_RETURN_SUCCESS;
};

@interface ClientTest : XCTestCase
@end

@implementation ClientTest

- (void)setUp {
  gDeleteClientSema = dispatch_semaphore_create(0);
}

- (void)testConstructors {
  // Ensure constructors set internal state properly
  // Anonymous scopes used to ensure destructors called as expected

  // Null `es_client_t*` *shouldn't* trigger `es_delete_client`
  {
    auto c = Client();
    XCTAssertEqual(c.Get(), nullptr);
    XCTAssertEqual(c.NewClientResult(), ES_NEW_CLIENT_RESULT_ERR_INTERNAL);
  }

  XCTAssertNotEqual(0,
                    dispatch_semaphore_wait(gDeleteClientSema,
                                            DISPATCH_TIME_NOW),
                    "es_delete_client called unexpectedly");

  // Nonnull `es_client_t*` *should* trigger `es_delete_client`
  {
    int fake;
    es_client_t *fake_client = (es_client_t*)&fake;
    auto c = Client(fake_client, ES_NEW_CLIENT_RESULT_SUCCESS);
    XCTAssertEqual(c.Get(), fake_client);
    XCTAssertEqual(c.NewClientResult(), ES_NEW_CLIENT_RESULT_SUCCESS);
  }

  XCTAssertEqual(0,
                dispatch_semaphore_wait(gDeleteClientSema,
                                        DISPATCH_TIME_NOW),
                "es_delete_client not called within expected time window");
}

- (void)testIsConnected {
  {
    auto c = Client();
    XCTAssertFalse(c.IsConnected());
  }

  {
    int fake;
    es_client_t *fake_client = (es_client_t*)&fake;
    auto c = Client(fake_client, ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED);
    XCTAssertFalse(c.IsConnected());
  }

  {
    int fake;
    es_client_t *fake_client = (es_client_t*)&fake;
    auto c = Client(fake_client, ES_NEW_CLIENT_RESULT_SUCCESS);
    XCTAssertTrue(c.IsConnected());
  }
}

@end
