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

#import <bsm/libbsm.h>
#include "gmock/gmock.h"
#import <DiskArbitration/DiskArbitration.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <sys/mount.h>

#include <memory>
#include <set>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#include "Source/common/TestUtils.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#import "Source/santad/EventProviders/DiskArbitrationTestUtil.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"

using santa::santad::event_providers::endpoint_security::Message;

@interface SNTEndpointSecurityDeviceManager (Testing)

- (void)logDiskAppeared:(NSDictionary*)props;

@end

@interface SNTEndpointSecurityDeviceManagerTest : XCTestCase
@property id mockConfigurator;
@end

@implementation SNTEndpointSecurityDeviceManagerTest

- (void)setUp {
  [super setUp];
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator eventLogType]).andReturn(-1);
}

- (std::pair<es_auth_result_t, bool>)triggerTestMountEvent:(SNTEndpointSecurityDeviceManager *)deviceManager
                                                 mockESApi:(std::shared_ptr<MockEndpointSecurityAPI>)mockESApi
                                                    mockDA:(MockDiskArbitration *)mockDA
                                                 eventType:(es_event_type_t)eventType
                                         diskInfoOverrides:(NSDictionary *)diskInfo
                                        expectedAuthResult:(es_auth_result_t)expectedAuthResult {
  [deviceManager enable];
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

  // Stub the log method since a mock `Logger` object isn't used.
  id partialDeviceManager = OCMPartialMock(deviceManager);
  OCMStub([partialDeviceManager logDiskAppeared:OCMOCK_ANY]);

  [mockDA insert:disk bsdName:test_mntfromname];

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(eventType, &proc, ActionType::Auth);
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  if (eventType == ES_EVENT_TYPE_AUTH_MOUNT) {
    esMsg.event.mount.statfs = &fs;
  } else if (eventType == ES_EVENT_TYPE_AUTH_REMOUNT) {
    esMsg.event.remount.statfs = &fs;
  } else {
    // Programming error. Fail the test.
    XCTAssertTrue(eventType == ES_EVENT_TYPE_AUTH_MOUNT ||
        eventType == ES_EVENT_TYPE_AUTH_REMOUNT);
  }

  __block es_auth_result_t authResult;
  __block bool cacheable;
  XCTestExpectation *mountExpectation =
      [self expectationWithDescription:@"Wait for response from ES"];


  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_,
                                            testing::_,
                                            expectedAuthResult,
                                            false))
      .WillOnce(testing::InvokeWithoutArgs(^bool{
        [mountExpectation fulfill];
        return true;
      }));

  {
    mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);
    Message msg(mockESApi, &esMsg);
    [deviceManager handleMessage:std::move(msg)];
  }

  [self waitForExpectations:@[ mountExpectation ] timeout:60.0];

  [partialDeviceManager stopMocking];

  return { authResult, cacheable };
}

- (void)testUSBBlockDisabled {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityDeviceManager *deviceManager =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                       logger:nullptr
                                              authResultCache:nullptr];
  deviceManager.blockUSBMount = NO;

  [self triggerTestMountEvent:deviceManager
                    mockESApi:mockESApi
                       mockDA:mockDA
                    eventType:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_ALLOW];
}

- (void)testRemount {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityDeviceManager *deviceManager =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                       logger:nullptr
                                              authResultCache:nullptr];

  deviceManager.blockUSBMount = YES;
  deviceManager.remountArgs = @[ @"noexec", @"rdonly" ];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for SNTDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString *> *gotRemountedArgs;
  deviceManager.deviceBlockCallback = ^(SNTDeviceEvent *event) {
    gotRemountedArgs = event.remountArgs;
    gotmntonname = event.mntonname;
    gotmntfromname = event.mntfromname;
    [expectation fulfill];
  };

  [self triggerTestMountEvent:deviceManager
                    mockESApi:mockESApi
                       mockDA:mockDA
                    eventType:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY];

  XCTAssertEqual(mockDA.wasRemounted, YES);

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqualObjects(gotRemountedArgs, deviceManager.remountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testBlockNoRemount {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityDeviceManager *deviceManager =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                       logger:nullptr
                                              authResultCache:nullptr];
  deviceManager.blockUSBMount = YES;

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for SNTDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString *> *gotRemountedArgs;
  deviceManager.deviceBlockCallback = ^(SNTDeviceEvent *event) {
    gotRemountedArgs = event.remountArgs;
    gotmntonname = event.mntonname;
    gotmntfromname = event.mntfromname;
    [expectation fulfill];
  };

  [self triggerTestMountEvent:deviceManager
                    mockESApi:mockESApi
                       mockDA:mockDA
                    eventType:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY];

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertNil(gotRemountedArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testEnsureRemountsCannotChangePerms {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityDeviceManager *deviceManager =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                       logger:nullptr
                                              authResultCache:nullptr];
  deviceManager.blockUSBMount = YES;
  deviceManager.remountArgs = @[ @"noexec", @"rdonly" ];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for SNTDeviceManager's blockCallback to trigger"];

  __block NSString *gotmntonname, *gotmntfromname;
  __block NSArray<NSString *> *gotRemountedArgs;
  deviceManager.deviceBlockCallback = ^(SNTDeviceEvent *event) {
    gotRemountedArgs = event.remountArgs;
    gotmntonname = event.mntonname;
    gotmntfromname = event.mntfromname;
    [expectation fulfill];
  };

  [self triggerTestMountEvent:deviceManager
                    mockESApi:mockESApi
                       mockDA:mockDA
                    eventType:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:nil
           expectedAuthResult:ES_AUTH_RESULT_DENY];

  XCTAssertEqual(mockDA.wasRemounted, YES);

  [self waitForExpectations:@[ expectation ] timeout:10.0];

  XCTAssertEqualObjects(gotRemountedArgs, deviceManager.remountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testEnsureDMGsDoNotPrompt {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityDeviceManager *deviceManager =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi
                                                       logger:nullptr
                                              authResultCache:nullptr];
  deviceManager.blockUSBMount = YES;
  deviceManager.remountArgs = @[ @"noexec", @"rdonly" ];

  deviceManager.deviceBlockCallback = ^(SNTDeviceEvent *event) {
    XCTFail(@"Should not be called");
  };

  NSDictionary *diskInfo = @{
    (__bridge NSString *)kDADiskDescriptionDeviceProtocolKey: @"Virtual Interface",
    (__bridge NSString *)kDADiskDescriptionDeviceModelKey: @"Disk Image",
    (__bridge NSString *)kDADiskDescriptionMediaNameKey: @"disk image",
  };

  [self triggerTestMountEvent:deviceManager
                    mockESApi:mockESApi
                       mockDA:mockDA
                    eventType:ES_EVENT_TYPE_AUTH_MOUNT
            diskInfoOverrides:diskInfo
           expectedAuthResult:ES_AUTH_RESULT_ALLOW];

  XCTAssertEqual(mockDA.wasRemounted, NO);
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_MOUNT,
      ES_EVENT_TYPE_AUTH_REMOUNT,
      ES_EVENT_TYPE_NOTIFY_UNMOUNT,
      };
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id deviceClient =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:mockESApi];

  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
    .After(
        EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
            .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  [deviceClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
