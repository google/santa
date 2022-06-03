#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"

#include <os/log.h>

namespace santa::santad::logs::endpoint_security::writers {

// TODO: Move this over to `syslog`...
void Syslog::Write(
    const std::vector<uint8_t> &bytes) {
  os_log(OS_LOG_DEFAULT, "%{public}s", bytes.data());
}

} // namespace santa::santad::logs::endpoint_security::writers
