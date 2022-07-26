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

#import <XCTest/XCTest.h>

#import "Source/santasyncservice/NSData+Zlib.h"

@interface NSDataZlibTest : XCTestCase
@end

@implementation NSDataZlibTest

- (void)setUp {
  [super setUp];
}

- (NSData *)dataFromFixture:(NSString *)file {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:file ofType:nil];
  XCTAssertNotNil(path, @"failed to load testdata: %@", file);
  return [NSData dataWithContentsOfFile:path];
}

- (void)testZlibCompressed {
  NSData *sut = [self dataFromFixture:@"sync_preflight_basic.json"];
  NSData *want = [self dataFromFixture:@"sync_preflight_basic.z"];

  XCTAssertEqualObjects([sut zlibCompressed], want);
}

- (void)testGzipCompressed {
  NSData *sut = [self dataFromFixture:@"sync_preflight_basic.json"];
  NSData *want = [self dataFromFixture:@"sync_preflight_basic.gz"];

  XCTAssertEqualObjects([sut gzipCompressed], want);
}

@end
