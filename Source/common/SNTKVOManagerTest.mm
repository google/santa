/// Copyright 2022 Google LLC
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

#import <XCTest/XCTest.h>

#import "Source/common/SNTKVOManager.h"

@interface Foo : NSObject
@property NSNumber *propNumber;
@property NSArray *propArray;
@property id propId;
@end

@implementation Foo
@end

@interface SNTKVOManagerTest : XCTestCase
@end

@implementation SNTKVOManagerTest

- (void)testInvalidSelector {
  Foo *foo = [[Foo alloc] init];

  SNTKVOManager *kvo = [[SNTKVOManager alloc] initWithObject:foo
                                        selector:NSSelectorFromString(@"doesNotExist")
                                            type:[NSNumber class]
                                        callback:^(id, id){
                                        }];

  XCTAssertNil(kvo);
}

- (void)testNormalOperation {
  Foo *foo = [[Foo alloc] init];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  int origVal = 123;
  int update1 = 456;
  int update2 = 789;

  foo.propNumber = @(origVal);

  // Store the values from the callback to test against expected values
  __block int oldVal;
  __block int newVal;

  SNTKVOManager *kvo = [[SNTKVOManager alloc] initWithObject:foo
                                        selector:@selector(propNumber)
                                            type:[NSNumber class]
                                        callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                          oldVal = [oldValue intValue];
                                          newVal = [newValue intValue];
                                          dispatch_semaphore_signal(sema);
                                        }];
  XCTAssertNotNil(kvo);

  // Ensure an update to the observed property triggers the callback
  foo.propNumber = @(update1);

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)),
                 "Failed waiting for first observable update");
  XCTAssertEqual(oldVal, origVal);
  XCTAssertEqual(newVal, update1);

  // One more time why not
  foo.propNumber = @(update2);

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)),
                 "Failed waiting for second observable update");
  XCTAssertEqual(oldVal, update1);
  XCTAssertEqual(newVal, update2);
}

- (void)testUnexpectedTypes {
  Foo *foo = [[Foo alloc] init];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  NSString *origVal = @"any_val";
  NSString *update = @"new_val";
  foo.propId = origVal;

  __block id oldVal;
  __block id newVal;

  SNTKVOManager *kvo = [[SNTKVOManager alloc] initWithObject:foo
                                        selector:@selector(propId)
                                            type:[NSString class]
                                        callback:^(id oldValue, id newValue) {
                                          oldVal = oldValue;
                                          newVal = newValue;
                                          dispatch_semaphore_signal(sema);
                                        }];
  XCTAssertNotNil(kvo);

  // Update to an unexpected type (here, NSNumber instead of NSString)
  foo.propId = @(123);

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)),
                 "Failed waiting for first observable update");
  XCTAssertEqualObjects(oldVal, origVal);
  XCTAssertNil(newVal);

  // Update again with an expected type, ensure oldVal is now nil
  foo.propId = update;

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)),
                 "Failed waiting for first observable update");
  XCTAssertNil(oldVal);
  XCTAssertEqualObjects(newVal, update);
}

@end
