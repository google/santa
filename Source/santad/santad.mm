#include "Source/santad/santad.h"

#include <memory>

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"

#import "Source/common/SNTLogging.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::writers::Syslog;
using santa::santad::logs::endpoint_security::Logger;

// TODO: Change return type
// int SantadMain(std::shared_ptr<EndpointSecurityAPI> es_api) {
int SantadMain() {
  SNTRuleTable *rule_table = [SNTDatabaseController ruleTable];
  if (!rule_table) {
    LOGE(@"Failed to initialize rule table.");
    exit(EXIT_FAILURE);
  }

  SNTEventTable *event_table = [SNTDatabaseController eventTable];
  if (!event_table) {
    LOGE(@"Failed to initialize event table.");
    exit(EXIT_FAILURE);
  }

  SNTCompilerController *compiler_controller = [[SNTCompilerController alloc] init];
  SNTNotificationQueue* notifier_queue = [[SNTNotificationQueue alloc] init];
  SNTSyncdQueue *syncd_queue = [[SNTSyncdQueue alloc] init];

  SNTExecutionController *exec_controller = [[SNTExecutionController alloc]
      initWithRuleTable:rule_table
             eventTable:event_table
          notifierQueue:notifier_queue
             syncdQueue:syncd_queue];

  auto es_api = std::make_shared<EndpointSecurityAPI>();
  std::shared_ptr<Enricher> enricher = std::make_shared<Enricher>();
  auto logger = std::make_shared<Logger>(std::make_unique<BasicString>(),
                                         std::make_unique<Syslog>());

  SNTEndpointSecurityRecorder *event_monitor = [[SNTEndpointSecurityRecorder alloc]
		initWithESAPI:es_api logger:logger enricher:enricher compilerController:compiler_controller];

  [event_monitor enable];

  return 0;
}
