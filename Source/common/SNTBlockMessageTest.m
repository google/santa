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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/SNTFileAccessEvent.h"
#include "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTSystemInfo.h"

@interface SNTBlockMessageTest : XCTestCase
@property id mockConfigurator;
@property id mockSystemInfo;
@end

@implementation SNTBlockMessageTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator machineID]).andReturn(@"my_mid");

  self.mockSystemInfo = OCMClassMock([SNTSystemInfo class]);
  OCMStub([self.mockSystemInfo longHostname]).andReturn(@"my_hn");
  OCMStub([self.mockSystemInfo hardwareUUID]).andReturn(@"my_u");
  OCMStub([self.mockSystemInfo serialNumber]).andReturn(@"my_s");
}

- (void)testEventDetailURLForEvent {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];

  se.fileSHA256 = @"my_fi";
  se.executingUser = @"my_un";
  se.fileBundleID = @"s.n.t";
  se.cdhash = @"abc";
  se.teamID = @"SNT";
  se.signingID = @"SNT:s.n.t";

  NSString *url = @"http://"
                  @"localhost?fs=%file_sha%&fi=%file_identifier%&bfi=%bundle_or_file_identifier%&"
                  @"fbid=%file_bundle_id%&ti=%team_id%&si=%signing_id%&ch=%cdhash%&"
                  @"un=%username%&mid=%machine_id%&hn=%hostname%&u=%uuid%&s=%serial%";
  NSString *wantUrl = @"http://"
                      @"localhost?fs=my_fi&fi=my_fi&bfi=my_fi&"
                      @"fbid=s.n.t&ti=SNT&si=SNT:s.n.t&ch=abc&"
                      @"un=my_un&mid=my_mid&hn=my_hn&u=my_u&s=my_s";

  NSURL *gotUrl = [SNTBlockMessage eventDetailURLForEvent:se customURL:url];

  // Set fileBundleHash and test again for newly expected values
  se.fileBundleHash = @"my_fbh";

  wantUrl = @"http://"
            @"localhost?fs=my_fbh&fi=my_fi&bfi=my_fbh&"
            @"fbid=s.n.t&ti=SNT&si=SNT:s.n.t&ch=abc&"
            @"un=my_un&mid=my_mid&hn=my_hn&u=my_u&s=my_s";

  gotUrl = [SNTBlockMessage eventDetailURLForEvent:se customURL:url];

  XCTAssertEqualObjects(gotUrl.absoluteString, wantUrl);

  XCTAssertNil([SNTBlockMessage eventDetailURLForEvent:se customURL:nil]);
  XCTAssertNil([SNTBlockMessage eventDetailURLForEvent:se customURL:@"null"]);
}

- (void)testEventDetailURLForFileAccessEvent {
  SNTFileAccessEvent *fae = [[SNTFileAccessEvent alloc] init];

  fae.ruleVersion = @"my_rv";
  fae.ruleName = @"my_rn";
  fae.fileSHA256 = @"my_fi";
  fae.fileBundleID = @"s.n.t";
  fae.cdhash = @"abc";
  fae.teamID = @"SNT";
  fae.signingID = @"SNT:s.n.t";
  fae.accessedPath = @"my_ap";
  fae.executingUser = @"my_un";

  NSString *url =
    @"http://"
    @"localhost?rv=%rule_version%&rn=%rule_name%&fi=%file_identifier%&"
    @"fbid=%file_bundle_id%&ti=%team_id%&si=%signing_id%&ch=%cdhash%&"
    @"ap=%accessed_path%&un=%username%&mid=%machine_id%&hn=%hostname%&u=%uuid%&s=%serial%";
  NSString *wantUrl = @"http://"
                      @"localhost?rv=my_rv&rn=my_rn&fi=my_fi&"
                      @"fbid=s.n.t&ti=SNT&si=SNT:s.n.t&ch=abc&"
                      @"ap=my_ap&un=my_un&mid=my_mid&hn=my_hn&u=my_u&s=my_s";

  NSURL *gotUrl = [SNTBlockMessage eventDetailURLForFileAccessEvent:fae customURL:url];

  XCTAssertEqualObjects(gotUrl.absoluteString, wantUrl);

  XCTAssertNil([SNTBlockMessage eventDetailURLForFileAccessEvent:fae customURL:nil]);
  XCTAssertNil([SNTBlockMessage eventDetailURLForFileAccessEvent:fae customURL:@"null"]);
}

- (void)testEventDetailURLMissingDetails {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];

  se.fileSHA256 = @"my_fi";

  NSString *url = @"http://localhost?fi=%file_identifier%";
  NSString *wantUrl = @"http://localhost?fi=my_fi";

  NSURL *gotUrl = [SNTBlockMessage eventDetailURLForEvent:se customURL:url];

  XCTAssertEqualObjects(gotUrl.absoluteString, wantUrl);
}

@end
