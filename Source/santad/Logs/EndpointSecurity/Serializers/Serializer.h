#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_SERIALIZER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_SERIALIZER_H

#include <memory>
#include <vector>

#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

namespace santa::santad::logs::endpoint_security::serializers {

class Serializer {
public:
  virtual ~Serializer() = default;
  // TODO: Return type should be suitable to pass to a serializer:
  std::vector<uint8_t> SerializeMessage(
      std::unique_ptr<santa::santad::event_providers::endpoint_security::EnrichedMessage> msg) {
    return std::visit([this](auto &&arg) {
      return this->SerializeMessage(arg);
    }, std::move(msg->msg_));
  }

  virtual std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedClose &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedExchange &) = 0;
  virtual std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedExec &) = 0;
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
};

} // namespace santa::santad::logs

#endif
