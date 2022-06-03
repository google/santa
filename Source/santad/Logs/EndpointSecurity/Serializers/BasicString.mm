#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"

#include <sstream>

#include <bsm/libbsm.h>

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedExit;

namespace santa::santad::logs::endpoint_security::serializers {

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec &msg) {
  std::stringstream ss;

  ss << "action=EXEC|pid=" << audit_token_to_pid(msg.es_msg_->process->audit_token)
    << "|instigator=" << msg.es_msg_->process->executable->path.data
    << "|new_image=" << msg.es_msg_->event.exec.target->executable->path.data;

  std::string s = ss.str();

  LOGE(@"Enriched exec: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedFork &msg) {
  std::stringstream ss;
  ss << "action=FORK|pid=" << msg.es_msg_->process->audit_token.val[5]
    << "|instigator=" << msg.es_msg_->process->executable->path.data
    << "|child_pid=" << audit_token_to_pid(msg.es_msg_->event.fork.child->audit_token);

  std::string s = ss.str();

  LOGE(@"Enriched fork: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExit &msg) {
  std::stringstream ss;
  ss << "action=EXIT|pid=" << msg.es_msg_->process->audit_token.val[5]
    << "|instigator=" << msg.es_msg_->process->executable->path.data
    << "|exit_status=" << msg.es_msg_->event.exit.stat;

  std::string s = ss.str();

  LOGE(@"Enriched exit: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace santa::santad::logs
