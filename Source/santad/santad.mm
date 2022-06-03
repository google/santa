#include "Source/santad/santad.h"

#include <memory>

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::writers::Syslog;
using santa::santad::logs::endpoint_security::Logger;

// TODO: Change return type
// int SantadMain(std::shared_ptr<EndpointSecurityAPI> es_api) {
int SantadMain() {
    auto esApi = std::make_shared<EndpointSecurityAPI>();

    // auto serializer =
    //   std::make_unique<BasicString>();
    // auto writer =
    //   std::make_unique<Syslog>();

    auto logger = std::make_shared<Logger>(std::make_unique<BasicString>(),
                                           std::make_unique<Syslog>());


  return 0;
}
