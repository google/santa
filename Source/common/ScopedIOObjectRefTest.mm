/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#import <XCTest/XCTest.h>

#include "Source/common/ScopedIOObjectRef.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

using santa::common::ScopedIOObjectRef;
using santa::santad::logs::endpoint_security::serializers::Utilities::GetDefaultIOKitCommsPort;

@interface ScopedIOObjectRefTest : XCTestCase
@end

@implementation ScopedIOObjectRefTest

- (void)testDefaultConstruction {
  // Default construction creates wraps a NULL object
  ScopedIOObjectRef<io_object_t> scopedRef;
  XCTAssertFalse(scopedRef.Unsafe());
}

- (void)testOperatorBool {
  // Operator bool is `false` when object is null
  {
    ScopedIOObjectRef<io_object_t> scopedNullRef;
    XCTAssertFalse(scopedNullRef.Unsafe());
    XCTAssertFalse(scopedNullRef);
  }

  // Operator bool is `true` when object is NOT null
  {
    CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
    XCTAssertNotEqual((CFMutableDictionaryRef)NULL, matchingDict);

    io_service_t service = IOServiceGetMatchingService(GetDefaultIOKitCommsPort(), matchingDict);

    ScopedIOObjectRef<io_service_t> scopedServiceRef =
      ScopedIOObjectRef<io_service_t>::Assume(service);

    XCTAssertTrue(scopedServiceRef.Unsafe());
    XCTAssertTrue(scopedServiceRef);
  }
}

- (void)testAssume {
  CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
  XCTAssertNotEqual((CFMutableDictionaryRef)NULL, matchingDict);

  io_service_t service = IOServiceGetMatchingService(GetDefaultIOKitCommsPort(), matchingDict);

  // Baseline state, initial retain count is 1 after object creation
  XCTAssertEqual(1, IOObjectGetUserRetainCount(service));
  XCTAssertNotEqual(IO_OBJECT_NULL, service);

  {
    ScopedIOObjectRef<io_service_t> scopedIORef = ScopedIOObjectRef<io_service_t>::Assume(service);

    // Ensure ownership was taken, and retain count remains unchanged
    XCTAssertTrue(scopedIORef.Unsafe());
    XCTAssertEqual(1, IOObjectGetUserRetainCount(scopedIORef.Unsafe()));
    XCTAssertNotEqual(IO_OBJECT_NULL, scopedIORef.Unsafe());
  }
}

- (void)testRetain {
  CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
  XCTAssertNotEqual((CFMutableDictionaryRef)NULL, matchingDict);

  io_service_t service = IOServiceGetMatchingService(GetDefaultIOKitCommsPort(), matchingDict);

  // Baseline state, initial retain count is 1 after object creation
  XCTAssertEqual(1, IOObjectGetUserRetainCount(service));
  XCTAssertNotEqual(IO_OBJECT_NULL, service);

  {
    ScopedIOObjectRef<io_service_t> scopedIORef = ScopedIOObjectRef<io_service_t>::Retain(service);

    // Ensure ownership was taken, and retain count was incremented
    XCTAssertTrue(scopedIORef.Unsafe());
    XCTAssertEqual(2, IOObjectGetUserRetainCount(scopedIORef.Unsafe()));
    XCTAssertNotEqual(IO_OBJECT_NULL, scopedIORef.Unsafe());
  }

  // The original `service` object should still be valid due to the extra retain.
  // Ensure the retain count has decreased since `scopedIORef` went out of scope.
  XCTAssertEqual(1, IOObjectGetUserRetainCount(service));
}

@end
