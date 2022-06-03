#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_SYSLOG_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_SYSLOG_H

#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

#include <vector>

namespace santa::santad::logs::endpoint_security::writers {

class Syslog
  : public Writer {
public:
  void Write(const std::vector<uint8_t> &bytes) override;
};

} // namespace santa::santad::logs::endpoint_security::writers

#endif
