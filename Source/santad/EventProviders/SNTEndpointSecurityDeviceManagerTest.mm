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

#import <DiskArbitration/DiskArbitration.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <bsm/libbsm.h>
#import <dispatch/dispatch.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/mount.h>
#include "gmock/gmock.h"

#include <memory>
#include <set>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#include "Source/common/TestUtils.h"
#import "Source/santad/EventProviders/DiskArbitrationTestUtil.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"

using santa::santad::event_providers::endpoint_security::Message;

@interface SNTEndpointSecurityDeviceManager (Testing)
- (void)logDiskAppeared:(NSDictionary *)props;
@end

@interface SNTEndpointSecurityDeviceManagerTest : XCTestCase
@property id mockConfigurator;
@property MockDiskArbitration *mockDA;
@end

@implementation SNTEndpointSecurityDeviceManagerTest

- (void)setUp {
  [super setUp];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator eventLogType]).andReturn(-1);

  self.mockDA = [MockDiskArbitration mockDiskArbitration];
  [self.mockDA reset];

  fclose(stdout);
}

- (void)triggerTestMountEvent:(es_event_type_t)eventType
            diskInfoOverrides:(NSDictionary *)diskInfo
           expectedAuthResult:(es_auth_result_t)expectedAuthResult
           deviceManagerSetup:(void (^)(SNTEndpointSecurityDeviceManager *))setupDMCallback {
  struct statfs fs = {0};
  NSString *test_mntfromname = @"/dev/disk2s1";
  NSString *test_mntonname = @"/Volumes/KATE'S 4G";

  strncpy(fs.f_mntfromname, [test_mntfromname UTF8String], sizeof(fs.f_mntfromname));
  strncpy(fs.f_mntonname, [test_mntonname UTF8String], sizeof(fs.f_mntonname));

  MockDADisk *disk = [[MockDADisk alloc] init];
  disk.diskDescription = @{
    (__bridge NSString *)kDADiskDescriptionDeviceProtocolKey : @"USB",
    (__bridge NSString *)kDADiskDescriptionMediaRemovableKey : @YES,
    @"DAVolumeMountable" : @YES,
    @"DAVolumePath" : test_mntonname,
    @"DADeviceModel" : @"Some device model",
    @"DADevicePath" : test_mntonname,
    @"DADeviceVendor" : @"Some vendor",
    @"DAAppearanceTime" : @0,
    @"DAMediaBSDName" : test_mntfromname,
  };

  if (diskInfo != nil) {
    NSMutableDictionary *mergedDiskDescription = [disk.diskDescription mutableCopy];
    for (NSString *key in diskInfo) {
      mergedDiskDescription[key] = diskInfo[key];
    }
    disk.diskDescription = (NSDictionary *)mergedDiskDescription;
  }

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityDeviceManager *deviceManager =
    [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                     logger:nullptr
                                            authResultCache:nullptr];

  setupDMCallback(deviceManager);

  // Stub the log method since a mock `Logger` object isn't used.
  id partialDeviceManager = OCMPartialMock(deviceManager);
  OCMStub([partialDeviceManager logDiskAppeared:OCMOCK_ANY]);

  [self.mockDA insert:disk bsdName:test_mntfromname];

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(eventType, &proc, ActionType::Auth, 6000);
  // Need a pointer to esMsg to capture in blocks below.
  es_message_t *heapESMsg = &esMsg;

  __block int retainCount = 0;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mockESApi, ReleaseMessage).WillRepeatedly(^{
    if (retainCount == 0) {
      XCTFail(@"Under retain!");
    }
    retainCount--;
    if (retainCount == 0) {
      dispatch_semaphore_signal(sema);
    }
  });
  EXPECT_CALL(*mockESApi, RetainMessage).WillRepeatedly(^{
    retainCount++;
    return heapESMsg;
  });

  if (eventType == ES_EVENT_TYPE_AUTH_MOUNT) {
    esMsg.event.mount.statfs = &fs;
  } else if (eventType == ES_EVENT_TYPE_AUTH_REMOUNT) {
    esMsg.event.remount.statfs = &fs;
  } else {
    // Programming error. Fail the test.
    XCTFail(@"Unhandled event type in test: %d", eventType);
  }

  XCTestExpectation *mountExpectation =
    [self expectationWithDescription:@"Wait for response from ES"];

  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_, testing::_, expectedAuthResult, false))
    .WillOnce(testing::InvokeWithoutArgs(^bool {
      [mountExpectation fulfill];
      return true;
    }));

  [deviceManager handleMessage:Message(mockESApi, &esMsg)];

  [self waitForExpectations:@[ mountExpectation ] timeout:60.0];

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 "Failed waiting for message to be processed...");

  [partialDeviceManager stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testUSBBlockDisabled {
  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager *dm) {
             dm.blockUSBMount = NO;
           }];
}

- (void)testRemount {
  NSArray *wantRemountArgs = @[ @"noexec", @"rdonly" ];

  XCTestExpectation *expectation =
    [self expectationWithDescription:
            @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString *> *gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager *dm) {
             dm.blockUSBMount = YES;
             dm.remountArgs = wantRemountArgs;

             dm.deviceBlockCallback = ^(SNTDeviceEvent *event) {
               gotRemountedArgs = event.remountArgs;
               gotmntonname = event.mntonname;
               gotmntfromname = event.mntfromname;
               [expectation fulfill];
             };
           }];

  XCTAssertEqual(self.mockDA.wasRemounted, YES);

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqualObjects(gotRemountedArgs, wantRemountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testBlockNoRemount {
  XCTestExpectation *expectation =
    [self expectationWithDescription:
            @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString *> *gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager *dm) {
             dm.blockUSBMount = YES;

             dm.deviceBlockCallback = ^(SNTDeviceEvent *event) {
               gotRemountedArgs = event.remountArgs;
               gotmntonname = event.mntonname;
               gotmntfromname = event.mntfromname;
               [expectation fulfill];
             };
           }];

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertNil(gotRemountedArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testEnsureRemountsCannotChangePerms {
  NSArray *wantRemountArgs = @[ @"noexec", @"rdonly" ];

  XCTestExpectation *expectation =
    [self expectationWithDescription:
            @"Wait for SNTEndpointSecurityDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString *> *gotRemountedArgs;

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager *dm) {
             dm.blockUSBMount = YES;
             dm.remountArgs = wantRemountArgs;

             dm.deviceBlockCallback = ^(SNTDeviceEvent *event) {
               gotRemountedArgs = event.remountArgs;
               gotmntonname = event.mntonname;
               gotmntfromname = event.mntfromname;
               [expectation fulfill];
             };
           }];

  XCTAssertEqual(self.mockDA.wasRemounted, YES);

  [self waitForExpectations:@[ expectation ] timeout:10.0];

  XCTAssertEqualObjects(gotRemountedArgs, wantRemountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testEnsureDMGsDoNotPrompt {
  NSArray *wantRemountArgs = @[ @"noexec", @"rdonly" ];
  NSDictionary *diskInfo = @{
    (__bridge NSString *)kDADiskDescriptionDeviceProtocolKey : @"Virtual Interface",
    (__bridge NSString *)kDADiskDescriptionDeviceModelKey : @"Disk Image",
    (__bridge NSString *)kDADiskDescriptionMediaNameKey : @"disk image",
  };

  [self triggerTestMountEvent:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:diskInfo
           expectedAuthResult:ES_AUTH_RESULT_ALLOW
           deviceManagerSetup:^(SNTEndpointSecurityDeviceManager *dm) {
             dm.blockUSBMount = YES;
             dm.remountArgs = wantRemountArgs;

             dm.deviceBlockCallback = ^(SNTDeviceEvent *event) {
               XCTFail(@"Should not be called");
             };
           }];

  XCTAssertEqual(self.mockDA.wasRemounted, NO);
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
    ES_EVENT_TYPE_AUTH_MOUNT,
    ES_EVENT_TYPE_AUTH_REMOUNT,
    ES_EVENT_TYPE_NOTIFY_UNMOUNT,
  };
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id deviceClient = [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi];

  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
    .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
             .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  [deviceClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
