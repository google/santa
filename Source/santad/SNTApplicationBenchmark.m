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
#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santad/SNTApplication.h"
#import "Source/santad/SNTDatabaseController.h"

#include "Source/santad/EventProviders/EndpointSecurityTestUtil.h"

@interface SNTApplicationBenchmark : XCTestCase
@property id mockSNTDatabaseController;
@property id mockConfigurator;
@end

@implementation SNTApplicationBenchmark : XCTestCase

- (void)setUp {
  [super setUp];
  fclose(stdout);
  self.mockSNTDatabaseController = OCMClassMock([SNTDatabaseController class]);
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator enableSysxCache]).andReturn(false);
}

+ (NSArray<XCTPerformanceMetric> *)defaultPerformanceMetrics {
  return @[
    XCTPerformanceMetric_WallClockTime,

    // Metrics visible and controllable from the XCode UI but without a symbol exposed for them:
    @"com.apple.XCTPerformanceMetric_RunTime",
    @"com.apple.XCTPerformanceMetric_UserTime",
    @"com.apple.XCTPerformanceMetric_SystemTime",
    @"com.apple.XCTPerformanceMetric_HighWaterMarkForHeapAllocations",
    @"com.apple.XCTPerformanceMetric_PersistentHeapAllocations",
    @"com.apple.XCTPerformanceMetric_PersistentHeapAllocationsNodes",
    @"com.apple.XCTPerformanceMetric_PersistentVMAllocations",
    @"com.apple.XCTPerformanceMetric_TotalHeapAllocationsKilobytes",
    @"com.apple.XCTPerformanceMetric_TransientHeapAllocationsKilobytes",
    @"com.apple.XCTPerformanceMetric_TransientHeapAllocationsNodes",
    @"com.apple.XCTPerformanceMetric_TransientVMAllocationsKilobytes",
    @"com.apple.XCTPerformanceMetric_HighWaterMarkForVMAllocations",
  ];
}

- (void)tearDown {
  [self.mockSNTDatabaseController stopMocking];
  [self.mockConfigurator stopMocking];
  [super tearDown];
}

- (void)executeAndMeasure:(NSString *)binaryName testPath:(NSString *)testPath {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];

  OCMStub([self.mockSNTDatabaseController databasePath]).andReturn(testPath);

  SNTApplication *app = [[SNTApplication alloc] init];
  [app start];

  // es events will start flowing in as soon as es_subscribe is called, regardless
  // of whether we're ready or not for it.
  XCTestExpectation *santaInit =
    [self expectationWithDescription:@"Wait for Santa to subscribe to EndpointSecurity"];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
    while ([mockES.subscriptions[ES_EVENT_TYPE_AUTH_EXEC] isEqualTo:@NO])
      ;

    [santaInit fulfill];
  });

  // Ugly hack to deflake the test and allow listenForDecisionRequests to install the correct
  // decision callback.
  [self waitForExpectations:@[ santaInit ] timeout:2.0];

  // MeasureMetrics actually runs all of the individual events asynchronously at once.
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  void (^executeBinary)(void) = ^void(void) {
    NSString *binaryPath = [NSString pathWithComponents:@[ testPath, binaryName ]];
    struct stat fileStat;
    lstat(binaryPath.UTF8String, &fileStat);

    ESMessage *msg = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
      m.binaryPath = binaryPath;
      m.executable->stat = fileStat;
      m.message->action_type = ES_ACTION_TYPE_AUTH;
      m.message->event_type = ES_EVENT_TYPE_AUTH_EXEC;
      m.message->event = (es_events_t){.exec = {.target = m.process}};
    }];

    __block BOOL complete = NO;
    [mockES registerResponseCallback:ES_EVENT_TYPE_AUTH_EXEC
                        withCallback:^(ESResponse *r) {
                          complete = YES;
                        }];

    [self startMeasuring];
    [mockES triggerHandler:msg.message];
    while (!complete)
      ;
    [self stopMeasuring];
    dispatch_semaphore_signal(sem);
  };

  [self measureMetrics:[SNTApplicationBenchmark defaultPerformanceMetrics]
    automaticallyStartMeasuring:false
                       forBlock:executeBinary];

  int sampleSize = 10;

  for (size_t i = 0; i < sampleSize; i++) {
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
  }
}

// Microbenchmarking analysis of binary execution
- (void)testMeasureExecutionDeny {
  NSString *testPath = @"santa/Source/santad/testdata/binaryrules";
  NSString *fullTestPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testPath
  ]];

  [self executeAndMeasure:@"badbinary" testPath:fullTestPath];
}

- (void)testMeasureExecutionAllow {
  NSString *testPath = @"santa/Source/santad/testdata/binaryrules";
  NSString *fullTestPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testPath
  ]];

  [self executeAndMeasure:@"goodbinary" testPath:fullTestPath];
}

@end
