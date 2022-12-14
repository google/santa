/// Copyright 2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_LOGGER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_LOGGER_H

#include <memory>
#include <string_view>

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

// Forward declarations
@class SNTStoredEvent;
namespace santa::santad::logs::endpoint_security {
class LoggerPeer;
}

namespace santa::santad::logs::endpoint_security {

class Logger {
 public:
  static std::unique_ptr<Logger> Create(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
    SNTEventLogType log_type, NSString *event_log_path, NSString *spool_log_path,
    size_t spool_dir_size_threshold, size_t spool_file_size_threshold,
    uint64_t spool_flush_timeout_ms);

  Logger(std::shared_ptr<serializers::Serializer> serializer,
         std::shared_ptr<writers::Writer> writer);

  virtual ~Logger() = default;

  virtual void Log(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EnrichedMessage> msg);

  void LogAllowlist(const santa::santad::event_providers::endpoint_security::Message &msg,
                    const std::string_view hash);

  void LogBundleHashingEvents(NSArray<SNTStoredEvent *> *events);

  void LogDiskAppeared(NSDictionary *props);
  void LogDiskDisappeared(NSDictionary *props);

  virtual void LogFileAccess(
    const std::string &policy_version, const std::string &policy_name,
    const santa::santad::event_providers::endpoint_security::Message &msg,
    const santa::santad::event_providers::endpoint_security::EnrichedProcess &enriched_process,
    const std::string &target, FileAccessPolicyDecision decision);

  friend class santa::santad::logs::endpoint_security::LoggerPeer;

 private:
  std::shared_ptr<serializers::Serializer> serializer_;
  std::shared_ptr<writers::Writer> writer_;
};

}  // namespace santa::santad::logs::endpoint_security

#endif
