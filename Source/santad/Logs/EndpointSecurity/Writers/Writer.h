#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_WRITER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_WRITER_H

#include <vector>

namespace santa::santad::logs::endpoint_security::writers {

class Writer {
public:
  virtual ~Writer() = default;

  virtual void Write(const std::vector<uint8_t> &bytes) = 0;
};

} // namespace santa::santad::logs::endpoint_security::writers

#endif
