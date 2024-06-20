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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_SERIALIZER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_SERIALIZER_H

#import <Foundation/Foundation.h>

#include <functional>
#include <memory>
#include <vector>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#import "Source/santad/SNTDecisionCache.h"

@class SNTStoredEvent;

namespace santa::santad::logs::endpoint_security::serializers {

class Serializer {
 public:
  Serializer(SNTDecisionCache *decision_cache);
  virtual ~Serializer() = default;

  std::vector<uint8_t> SerializeMessage(
    std::unique_ptr<santa::santad::event_providers::endpoint_security::EnrichedMessage> msg) {
    return std::visit([this](const auto &arg) { return this->SerializeMessageTemplate(arg); },
                      msg->GetEnrichedMessage());
  }

  bool EnabledMachineID();
  std::string_view MachineID();

  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedClose &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExchange &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExec &,
    SNTCachedDecision *cd) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedExit &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedFork &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLink &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedRename &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedUnlink &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedCSInvalidated &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLogin &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLogout
      &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLock &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionUnlock
      &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedScreenSharingAttach &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedScreenSharingDetach &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedOpenSSHLogin &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedOpenSSHLogout &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginLogin &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
    const santa::santad::event_providers::endpoint_security::EnrichedLoginLogout &) = 0;

  virtual std::vector<uint8_t> SerializeFileAccess(
    const std::string &policy_version, const std::string &policy_name,
    const santa::santad::event_providers::endpoint_security::Message &msg,
    const santa::santad::event_providers::endpoint_security::EnrichedProcess &enriched_process,
    const std::string &target, FileAccessPolicyDecision decision) = 0;

  virtual std::vector<uint8_t> SerializeAllowlist(
    const santa::santad::event_providers::endpoint_security::Message &, const std::string_view) = 0;

  virtual std::vector<uint8_t> SerializeBundleHashingEvent(SNTStoredEvent *) = 0;

  virtual std::vector<uint8_t> SerializeDiskAppeared(NSDictionary *) = 0;
  virtual std::vector<uint8_t> SerializeDiskDisappeared(NSDictionary *) = 0;

 private:
  // Template pattern methods used to ensure a place to implement any desired
  // functionality that shouldn't be overridden by derived classes.
  // The default implementation acts as a pass-through.
  // Define type-specific specializations when requried.
  std::vector<uint8_t> SerializeMessageTemplate(
    const santa::santad::event_providers::endpoint_security::EnrichedExec &);

  template <typename T>
  std::vector<uint8_t> SerializeMessageTemplate(const T &msg) {
    return SerializeMessage(msg);
  }

  bool enabled_machine_id_ = false;
  std::string machine_id_;
  SNTDecisionCache *decision_cache_;
};

}  // namespace santa::santad::logs::endpoint_security::serializers

#endif
