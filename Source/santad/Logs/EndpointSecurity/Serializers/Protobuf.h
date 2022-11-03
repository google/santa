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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_PROTOBUF_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_PROTOBUF_H

#import <Foundation/Foundation.h>
#include <google/protobuf/arena.h>

#include <memory>
#include <vector>

#include "Source/common/santa_proto_include_wrapper.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "absl/synchronization/mutex.h"

// Forward declarations
namespace santa::santad::logs::endpoint_security::serializers {
class ProtobufPeer;
}

namespace santa::santad::logs::endpoint_security::serializers {

class Protobuf : public Serializer {
 public:
  using Serializer::SerializeMessage;

  static std::shared_ptr<Protobuf> Create(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi);

  Protobuf(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi);

  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedClose &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExchange &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExec &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExit &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedFork &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLink &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedRename &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedUnlink &) override;

  std::vector<uint8_t> SerializeAllowlist(
    const santa::santad::event_providers::endpoint_security::Message &,
    const std::string_view) override;

  std::vector<uint8_t> SerializeBundleHashingEvent(SNTStoredEvent *) override;

  std::vector<uint8_t> SerializeDiskAppeared(NSDictionary *) override;
  std::vector<uint8_t> SerializeDiskDisappeared(NSDictionary *) override;

  virtual bool Drain(std::string *output, size_t threshold);

  // Peer class for testing
  friend class santa::santad::logs::endpoint_security::serializers::ProtobufPeer;

 private:
  ::santa::pb::v1::SantaMessage *CreateDefaultProto();
  ::santa::pb::v1::SantaMessage *CreateDefaultProto(
    const santa::santad::event_providers::endpoint_security::EnrichedEventType &msg);
  ::santa::pb::v1::SantaMessage *CreateDefaultProto(struct timespec event_time,
                                                    struct timespec processed_time);

  std::vector<uint8_t> FinalizeProto(::santa::pb::v1::SantaMessage *santa_msg);

  std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi_;

  google::protobuf::Arena arena_;
  absl::Mutex batch_lock_;
  ::santa::pb::v1::SantaMessageBatch *santa_message_batch_;
  ABSL_GUARDED_BY(batch_lock_) size_t bytes_batched_ = 0;
};

}  // namespace santa::santad::logs::endpoint_security::serializers

#endif
