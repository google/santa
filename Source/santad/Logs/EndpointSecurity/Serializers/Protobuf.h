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

#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#include "Source/common/santa_proto_include_wrapper.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"

namespace santa {

class Protobuf : public Serializer {
 public:
  static std::shared_ptr<Protobuf> Create(std::shared_ptr<santa::EndpointSecurityAPI> esapi,
                                          SNTDecisionCache *decision_cache, bool json = false);

  Protobuf(std::shared_ptr<santa::EndpointSecurityAPI> esapi, SNTDecisionCache *decision_cache,
           bool json = false);

  std::vector<uint8_t> SerializeMessage(const santa::EnrichedClose &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedExchange &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedExec &, SNTCachedDecision *) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedExit &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedFork &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLink &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedRename &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedUnlink &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedCSInvalidated &) override;
#if HAVE_MACOS_13
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionLogin &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionLogout &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionLock &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionUnlock &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedScreenSharingAttach &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedScreenSharingDetach &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedOpenSSHLogin &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedOpenSSHLogout &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginLogin &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginLogout &) override;
#endif

  std::vector<uint8_t> SerializeFileAccess(const std::string &policy_version,
                                           const std::string &policy_name,
                                           const santa::Message &msg,
                                           const santa::EnrichedProcess &enriched_process,
                                           const std::string &target,
                                           FileAccessPolicyDecision decision) override;

  std::vector<uint8_t> SerializeAllowlist(const santa::Message &, const std::string_view) override;

  std::vector<uint8_t> SerializeBundleHashingEvent(SNTStoredEvent *) override;

  std::vector<uint8_t> SerializeDiskAppeared(NSDictionary *) override;
  std::vector<uint8_t> SerializeDiskDisappeared(NSDictionary *) override;

 private:
  ::santa::pb::v1::SantaMessage *CreateDefaultProto(google::protobuf::Arena *arena);
  ::santa::pb::v1::SantaMessage *CreateDefaultProto(google::protobuf::Arena *arena,
                                                    const santa::EnrichedEventType &msg);
  ::santa::pb::v1::SantaMessage *CreateDefaultProto(google::protobuf::Arena *arena,
                                                    const santa::Message &msg);
  ::santa::pb::v1::SantaMessage *CreateDefaultProto(google::protobuf::Arena *arena,
                                                    struct timespec event_time,
                                                    struct timespec processed_time);

  std::vector<uint8_t> FinalizeProto(::santa::pb::v1::SantaMessage *santa_msg);

  std::shared_ptr<santa::EndpointSecurityAPI> esapi_;
  // Toggle for transforming protobuf output to its JSON form.
  // See https://protobuf.dev/programming-guides/proto3/#json
  bool json_;
};

}  // namespace santa

#endif
