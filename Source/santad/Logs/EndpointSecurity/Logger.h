#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_LOGGER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_LOGGER_H

#include <memory>

#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

namespace santa::santad::logs::endpoint_security {

class Logger {
public:
  Logger(std::unique_ptr<serializers::Serializer> serializer,
                 std::unique_ptr<writers::Writer> writer)
      : serializer_(std::move(serializer)), writer_(std::move(writer)) {}

  void Log(
      std::unique_ptr<santa::santad::event_providers::endpoint_security::EnrichedMessage> msg) {
    writer_->Write(serializer_->SerializeMessage(std::move(msg)));
  }

private:
  std::unique_ptr<serializers::Serializer> serializer_;
  std::unique_ptr<writers::Writer> writer_;
};

} // namespace santa::santad::logs::endpoint_security

#endif
