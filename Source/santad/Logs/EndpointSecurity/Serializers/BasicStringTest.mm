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

#include <EndpointSecurity/ESTypes.h>
#include <bsm/libbsm.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <string>

#import "Source/common/SNTStoredEvent.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::serializers::Serializer;

class MockEndpointSecurityAPI : public EndpointSecurityAPI {
public:
  MOCK_METHOD(es_message_t*, RetainMessage, (const es_message_t* msg));
  MOCK_METHOD(void, ReleaseMessage, (es_message_t* msg));
};

#define NOBODY ((unsigned int)-2)

audit_token_t MakeAuditToken(pid_t pid, pid_t pidver) {
  return audit_token_t{
    .val = {
      0, NOBODY, NOBODY, NOBODY, NOBODY, (unsigned int)pid, 0, (unsigned int)pidver,
    },
  };
}

es_string_token_t MakeStringToken(const char* s) {
  return (es_string_token_t){
    .length = strlen(s),
    .data = s,
  };
}

es_file_t MakeESFile(const char *path) {
  return es_file_t{
    .path = MakeStringToken(path),
    .path_truncated = false,
    .stat = {}
  };
}

es_process_t MakeESProcess(es_file_t *es_file,
                           audit_token_t tok,
                           audit_token_t parent_tok) {
  return es_process_t{
    .audit_token = tok,
    .ppid = audit_token_to_pid(parent_tok),
    .original_ppid = audit_token_to_pid(parent_tok),
    .executable = es_file,
    .parent_audit_token = parent_tok,
  };
}

es_message_t MakeESMessage(es_event_type_t event_type,
                           es_process_t *instigator) {
  return es_message_t{
    .event_type = event_type,
    .process = instigator,
  };
}


TEST(BasicString, SerializeMessageRename) {
  es_file_t proc_file = MakeESFile("foobar");
  es_file_t src_file = MakeESFile("src");
  es_file_t dst_file = MakeESFile("dst");
  es_process_t proc = MakeESProcess(&proc_file,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(56, 78));
  es_message_t es_msg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &proc);
  es_msg.event.rename.source = &src_file;
  es_msg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
  es_msg.event.rename.destination.existing_file = &dst_file;

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .After(EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
          .WillOnce(testing::Return(&es_msg)));

  Message msg(mock_esapi, &es_msg);

  Enricher enricher;

  std::shared_ptr<EnrichedMessage> enriched_message = enricher.Enrich(std::move(msg));

  std::shared_ptr<Serializer> bs = BasicString::Create(false);
  auto ret = bs->SerializeMessage(enriched_message);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=RENAME|path=src|newpath=dst|pid=12|ppid=56"
      "|process=foobar|processpath=foobar|uid=-2|user=nobody"
      "|gid=-2|group=nobody";

  EXPECT_EQ(want, got);
}

TEST(BasicString, SerializeMessageUnlink) {
  es_file_t proc_file = MakeESFile("foobar");
  es_file_t target_file = MakeESFile("deleted_file");
  es_process_t proc = MakeESProcess(&proc_file,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(56, 78));
  es_message_t es_msg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_UNLINK, &proc);
  es_msg.event.unlink.target = &target_file;

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .After(EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
          .WillOnce(testing::Return(&es_msg)));

  Message msg(mock_esapi, &es_msg);

  Enricher enricher;

  std::shared_ptr<EnrichedMessage> enriched_message = enricher.Enrich(std::move(msg));

  std::shared_ptr<Serializer> bs = BasicString::Create(false);
  auto ret = bs->SerializeMessage(enriched_message);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DELETE|path=deleted_file|pid=12|ppid=56"
      "|process=foobar|processpath=foobar|uid=-2|user=nobody"
      "|gid=-2|group=nobody";

  EXPECT_EQ(want, got);

}

TEST(BasicString, SerializeAllowlist) {
  es_file_t file = MakeESFile("foobar");
  es_process_t proc = MakeESProcess(&file,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(56, 78));
  es_message_t es_msg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
  es_msg.event.close.target = &file;

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();

  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .After(EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
          .WillOnce(testing::Return(&es_msg)));
  Message msg(mock_esapi, &es_msg);

  auto bs = BasicString::Create(false);
  auto ret = bs->SerializeAllowlist(msg, "test_hash");
  std::string got(ret.begin(), ret.end());

  std::string want = "action=ALLOWLIST|pid=12|pidversion=34|path=foobar|sha256=test_hash";

  EXPECT_EQ(want, got);
}

TEST(BasicString, SerializeBundleHashingEvent) {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];

  se.fileSHA256 = @"file_hash";
  se.fileBundleHash = @"file_bundle_hash";
  se.fileBundleName = @"file_bundle_Name";
  se.fileBundleID = nil;
  se.fileBundlePath = @"file_bundle_path";
  se.filePath = @"file_path";

  auto bs = BasicString::Create(false);
  auto ret = bs->SerializeBundleHashingEvent(se);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=BUNDLE|sha256=file_hash"
      "|bundlehash=file_bundle_hash|bundlename=file_bundle_Name|bundleid="
      "|bundlepath=file_bundle_path|path=file_path";

  EXPECT_EQ(want, got);
}

TEST(BasicString, SerializeDiskAppeared) {
  NSDictionary *props = @{
    @"DADevicePath": @"",
    @"DADeviceVendor": @"vendor",
    @"DADeviceModel": @"model",
    @"DAAppearanceTime": @(1252487349), // 2009-09-09 09:09:09
    @"DAVolumePath": [NSURL URLWithString:@"path"],
    @"DAMediaBSDName": @"bsd",
    @"DAVolumeKind": @"apfs",
    @"DADeviceProtocol": @"usb",
  };

  auto bs = BasicString::Create(false);
  auto ret = bs->SerializeDiskAppeared(props);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DISKAPPEAR|mount=path|volume=|bsdname=bsd|fs=apfs"
      "|model=vendor model|serial=|bus=usb|dmgpath="
      "|appearance=2040-09-09T09:09:09.000Z";

  EXPECT_EQ(want, got);
}

TEST(BasicString, SerializeDiskDisappeared) {
  NSDictionary *props = @{
    @"DAVolumePath": [NSURL URLWithString:@"path"],
    @"DAMediaBSDName": @"bsd",
  };

  auto bs = BasicString::Create(false);
  auto ret = bs->SerializeDiskDisappeared(props);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DISKDISAPPEAR|mount=path|volume=|bsdname=bsd";

  EXPECT_EQ(want, got);
}
