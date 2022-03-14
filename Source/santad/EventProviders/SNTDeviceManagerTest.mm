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
#import <DiskArbitration/DiskArbitration.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <bsm/libbsm.h>

#include <sys/mount.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/santad/EventProviders/SNTDeviceManager.h"

#import "Source/santad/EventProviders/DiskArbitrationTestUtil.h"
#import "Source/santad/EventProviders/EndpointSecurityTestUtil.h"

@interface SNTDeviceManagerTest : XCTestCase
@property id mockConfigurator;
@end

@implementation SNTDeviceManagerTest

- (void)setUp {
  [super setUp];
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator eventLogType]).andReturn(-1);

  fclose(stdout);
}

- (ESResponse *)triggerTestMount:(SNTDeviceManager *)deviceManager
                          mockES:(MockEndpointSecurity *)mockES
                          mockDA:(MockDiskArbitration *)mockDA {
  if (!deviceManager.subscribed) {
    // [deviceManager listen] is synchronous, but we want to asynchronously dispatch it
    // with an enforced timeout to ensure that we never run into issues where the client
    // never instantiates.
    XCTestExpectation *initExpectation =
      [self expectationWithDescription:@"Wait for SNTDeviceManager to instantiate"];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
      [deviceManager listen];
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
      while (!deviceManager.subscribed)
        ;
      [initExpectation fulfill];
    });
    [self waitForExpectations:@[ initExpectation ] timeout:60.0];
  }

  struct statfs *fs = static_cast<struct statfs *>(calloc(1, sizeof(struct statfs)));
  NSString *test_mntfromname = @"/dev/disk2s1";
  NSString *test_mntonname = @"/Volumes/KATE'S 4G";
  const char *c_mntfromname = [test_mntfromname UTF8String];
  const char *c_mntonname = [test_mntonname UTF8String];

  strncpy(fs->f_mntfromname, c_mntfromname, MAXPATHLEN);
  strncpy(fs->f_mntonname, c_mntonname, MAXPATHLEN);

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

  [mockDA insert:disk bsdName:test_mntfromname];

  ESMessage *m = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
    m.binaryPath = @"/System/Library/Filesystems/msdos.fs/Contents/Resources/mount_msdos";
    m.message->action_type = ES_ACTION_TYPE_AUTH;
    m.message->event_type = ES_EVENT_TYPE_AUTH_MOUNT;
    m.message->event = (es_events_t){.mount = {.statfs = fs}};
  }];

  XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];
  __block ESResponse *got;
  [mockES registerResponseCallback:ES_EVENT_TYPE_AUTH_MOUNT
                      withCallback:^(ESResponse *r) {
                        got = r;
                        [expectation fulfill];
                      }];

  [mockES triggerHandler:m.message];

  [self waitForExpectations:@[ expectation ] timeout:60.0];
  free(fs);

  return got;
}

- (void)testUSBBlockDisabled {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];

  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  SNTDeviceManager *deviceManager = [[SNTDeviceManager alloc] init];
  deviceManager.blockUSBMount = NO;
  ESResponse *got = [self triggerTestMount:deviceManager mockES:mockES mockDA:mockDA];
  XCTAssertEqual(got.result, ES_AUTH_RESULT_ALLOW);
}

- (void)testRemount {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];

  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  SNTDeviceManager *deviceManager = [[SNTDeviceManager alloc] init];
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

  ESResponse *got = [self triggerTestMount:deviceManager mockES:mockES mockDA:mockDA];

  XCTAssertEqual(got.result, ES_AUTH_RESULT_DENY);
  XCTAssertEqual(mockDA.wasRemounted, YES);

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqualObjects(gotRemountedArgs, deviceManager.remountArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

- (void)testBlockNoRemount {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];

  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA reset];

  SNTDeviceManager *deviceManager = [[SNTDeviceManager alloc] init];
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

  ESResponse *got = [self triggerTestMount:deviceManager mockES:mockES mockDA:mockDA];

  XCTAssertEqual(got.result, ES_AUTH_RESULT_DENY);

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertNil(gotRemountedArgs);
  XCTAssertEqualObjects(gotmntonname, @"/Volumes/KATE'S 4G");
  XCTAssertEqualObjects(gotmntfromname, @"/dev/disk2s1");
}

@end
