#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_BASICSTRING_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_BASICSTRING_H

#include <memory>
#include <vector>

#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"

namespace santa::santad::logs::endpoint_security::serializers {

class BasicString
  : public Serializer {
public:
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
};

} // namespace santa::santad::logs::endpoint_security::serializers

#endif
