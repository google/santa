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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_BASICSTRING_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_BASICSTRING_H

#import <Foundation/Foundation.h>

#include <memory>
#include <sstream>
#include <vector>

#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"

namespace santa::santad::logs::endpoint_security::serializers {

class BasicString : public Serializer {
 public:
  static std::shared_ptr<BasicString> Create(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
    SNTDecisionCache *decision_cache, bool prefix_time_name = true);

  BasicString(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
    SNTDecisionCache *decision_cache, bool prefix_time_name);

  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedClose &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExchange &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExec &,
    SNTCachedDecision *) override;
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
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedCSInvalidated &) override;
#if HAVE_MACOS_13
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLogin &)
    override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLogout &)
    override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLock &)
    override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionUnlock &)
    override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedScreenSharingAttach &)
    override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedScreenSharingDetach &)
    override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedOpenSSHLogin &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedOpenSSHLogout &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginLogin &) override;
  std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginLogout &) override;
#endif

  std::vector<uint8_t> SerializeFileAccess(
    const std::string &policy_version, const std::string &policy_name,
    const santa::santad::event_providers::endpoint_security::Message &msg,
    const santa::santad::event_providers::endpoint_security::EnrichedProcess &enriched_process,
    const std::string &target, FileAccessPolicyDecision decision) override;

  std::vector<uint8_t> SerializeAllowlist(
    const santa::santad::event_providers::endpoint_security::Message &,
    const std::string_view) override;

  std::vector<uint8_t> SerializeBundleHashingEvent(SNTStoredEvent *) override;

  std::vector<uint8_t> SerializeDiskAppeared(NSDictionary *) override;
  std::vector<uint8_t> SerializeDiskDisappeared(NSDictionary *) override;

 private:
  std::string CreateDefaultString(size_t reserved_size = 512);
  std::vector<uint8_t> FinalizeString(std::string &str);

  std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi_;
  bool prefix_time_name_;
};

}  // namespace santa::santad::logs::endpoint_security::serializers

#endif
