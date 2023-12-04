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
#include <Security/Security.h>
#import <XCTest/XCTest.h>
#include "XCTest/XCTest.h"

#include "Source/common/ScopedCFTypeRef.h"

using santa::common::ScopedCFTypeRef;

@interface ScopedCFTypeRefTest : XCTestCase
@end

@implementation ScopedCFTypeRefTest

- (void)testDefaultConstruction {
  // Default construction creates wraps a NULL object
  ScopedCFTypeRef<CFNumberRef> scopedRef;
  XCTAssertFalse(scopedRef.Unsafe());
}

- (void)testOperatorBool {
  // Operator bool is `false` when object is null
  {
    ScopedCFTypeRef<CFNumberRef> scopedNullRef;
    XCTAssertFalse(scopedNullRef.Unsafe());
    XCTAssertFalse(scopedNullRef);
  }

  // Operator bool is `true` when object is NOT null
  {
    int x = 123;
    CFNumberRef numRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &x);

    ScopedCFTypeRef<CFNumberRef> scopedNumRef = ScopedCFTypeRef<CFNumberRef>::Assume(numRef);
    XCTAssertTrue(scopedNumRef.Unsafe());
    XCTAssertTrue(scopedNumRef);
  }
}

// Note that CFMutableArray is used for testing, even when subtypes aren't
// needed, because it is never optimized into immortal constant values, unlike
// other types.
- (void)testAssume {
  int want = 123;
  int got = 0;
  CFMutableArrayRef array = CFArrayCreateMutable(nullptr, /*capacity=*/0, &kCFTypeArrayCallBacks);

  // Baseline state, initial retain count is 1 after object creation
  XCTAssertEqual(1, CFGetRetainCount(array));

  CFNumberRef numRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &want);
  CFArrayAppendValue(array, numRef);
  CFRelease(numRef);

  XCTAssertEqual(1, CFArrayGetCount(array));

  {
    ScopedCFTypeRef<CFMutableArrayRef> scopedArray =
      ScopedCFTypeRef<CFMutableArrayRef>::Assume(array);

    // Ensure ownership was taken, and retain count remains unchanged
    XCTAssertTrue(scopedArray.Unsafe());
    XCTAssertEqual(1, CFGetRetainCount(scopedArray.Unsafe()));

    // Make sure the object contains expected contents
    CFMutableArrayRef ref = scopedArray.Unsafe();
    XCTAssertEqual(1, CFArrayGetCount(ref));
    XCTAssertTrue(
      CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(ref, 0), kCFNumberIntType, &got));
    XCTAssertEqual(want, got);
  }
}

// Note that CFMutableArray is used for testing, even when subtypes aren't
// needed, because it is never optimized into immortal constant values, unlike
// other types.
- (void)testRetain {
  int want = 123;
  int got = 0;
  CFMutableArrayRef array = CFArrayCreateMutable(nullptr, /*capacity=*/0, &kCFTypeArrayCallBacks);

  // Baseline state, initial retain count is 1 after object creation
  XCTAssertEqual(1, CFGetRetainCount(array));

  CFNumberRef numRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &want);
  CFArrayAppendValue(array, numRef);
  CFRelease(numRef);

  XCTAssertEqual(1, CFArrayGetCount(array));

  {
    ScopedCFTypeRef<CFMutableArrayRef> scopedArray =
      ScopedCFTypeRef<CFMutableArrayRef>::Retain(array);

    // Ensure ownership was taken, and retain count was incremented
    XCTAssertTrue(scopedArray.Unsafe());
    XCTAssertEqual(2, CFGetRetainCount(scopedArray.Unsafe()));

    // Make sure the object contains expected contents
    CFMutableArrayRef ref = scopedArray.Unsafe();
    XCTAssertEqual(1, CFArrayGetCount(ref));
    XCTAssertTrue(
      CFNumberGetValue((CFNumberRef)CFArrayGetValueAtIndex(ref, 0), kCFNumberIntType, &got));
    XCTAssertEqual(want, got);
  }

  // The original `array` object should still be invalid due to the extra retain.
  // Ensure the retain count has decreased since `scopedArray` went out of scope
  XCTAssertEqual(1, CFArrayGetCount(array));
}

- (void)testInto {
  ScopedCFTypeRef<CFURLRef> scopedURLRef =
    ScopedCFTypeRef<CFURLRef>::Assume(CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault, CFSTR("/usr/bin/true"), kCFURLPOSIXPathStyle, YES));

  ScopedCFTypeRef<SecStaticCodeRef> scopedCodeRef;
  XCTAssertFalse(scopedCodeRef);

  SecStaticCodeCreateWithPath(scopedURLRef.Unsafe(), kSecCSDefaultFlags,
                              scopedCodeRef.InitializeInto());

  // Ensure the scoped object was initialized
  XCTAssertTrue(scopedCodeRef);
}

@end
