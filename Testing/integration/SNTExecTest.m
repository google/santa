/// Copyright 2021 Google Inc. All rights reserved.
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
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <unistd.h>

@interface SNTExecTest : XCTestCase
@end

@implementation SNTExecTest : XCTestCase
- (void)setUp {
  [super setUp];
  fclose(stdout);
}

- (void)checkExecution:(NSString *)path shouldExec:(BOOL)shouldExec {
  __block int status;

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for test binary to execute"];

  __block NSTask *task = [[NSTask alloc] init];
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
    task.launchPath = path;
    [task launch];
    [task waitUntilExit];
    status = [task terminationStatus];
    [expectation fulfill];
  });

  [self waitForExpectationsWithTimeout:20.0
                               handler:^(NSError *error) {
                                 XCTAssertFalse([task isRunning], @"Test timed out: %@", error);
                                 [task terminate];
                               }];

  BOOL didExec = (status == 0);
  XCTAssertEqual(didExec, shouldExec);
}

- (void)testShouldExecute {
  NSString *testPath = @"santa/Source/santad/testdata/binaryrules";
  NSString *fullTestPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testPath
  ]];
  NSDictionary *testCases = @{
    @"goodbinary" : @YES,
    @"badbinary" : @NO,
    @"noop" : @YES,
  };
  for (NSString *binary in testCases) {
    [self checkExecution:[NSString pathWithComponents:@[ fullTestPath, binary ]]
              shouldExec:[testCases[binary] boolValue]];
  }
}

@end
