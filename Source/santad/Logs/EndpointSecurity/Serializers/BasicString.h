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
      const santa::santad::event_providers::endpoint_security::EnrichedExec &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedFork &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedExit &) override;
};

} // namespace santa::santad::logs::endpoint_security::serializers

#endif
