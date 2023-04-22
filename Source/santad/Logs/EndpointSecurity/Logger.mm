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

#include "Source/santad/Logs/EndpointSecurity/Logger.h"

#include "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTLogging.h"
#include "Source/common/SNTStoredEvent.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Null.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#include "Source/santad/SNTDecisionCache.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::EnrichedProcess;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::serializers::ClientModeFunc;
using santa::santad::logs::endpoint_security::serializers::Empty;
using santa::santad::logs::endpoint_security::serializers::Protobuf;
using santa::santad::logs::endpoint_security::writers::File;
using santa::santad::logs::endpoint_security::writers::Null;
using santa::santad::logs::endpoint_security::writers::Spool;
using santa::santad::logs::endpoint_security::writers::Syslog;

namespace santa::santad::logs::endpoint_security {

// Flush the write buffer every 5 seconds
static const uint64_t kFlushBufferTimeoutMS = 10000;
// Batch writes up to 128kb
static const size_t kBufferBatchSizeBytes = (1024 * 128);
// Reserve an extra 4kb of buffer space to account for event overflow
static const size_t kMaxExpectedWriteSizeBytes = 4096;

// Translate configured log type to appropriate Serializer/Writer pairs
std::unique_ptr<Logger> Logger::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                       SNTEventLogType log_type, SNTDecisionCache *decision_cache,
                                       ClientModeFunc GetClientMode, NSString *event_log_path,
                                       NSString *spool_log_path, size_t spool_dir_size_threshold,
                                       size_t spool_file_size_threshold,
                                       uint64_t spool_flush_timeout_ms) {
  switch (log_type) {
    case SNTEventLogTypeFilelog:
      return std::make_unique<Logger>(
        BasicString::Create(esapi, std::move(decision_cache), std::move(GetClientMode)),
        File::Create(event_log_path, kFlushBufferTimeoutMS, kBufferBatchSizeBytes,
                     kMaxExpectedWriteSizeBytes));
    case SNTEventLogTypeSyslog:
      return std::make_unique<Logger>(
        BasicString::Create(esapi, std::move(decision_cache), std::move(GetClientMode), false),
        Syslog::Create());
    case SNTEventLogTypeNull: return std::make_unique<Logger>(Empty::Create(), Null::Create());
    case SNTEventLogTypeProtobuf:
      LOGW(@"The EventLogType value protobuf is currently in beta. The protobuf schema is subject "
           @"to change.");
      return std::make_unique<Logger>(
        Protobuf::Create(esapi, std::move(decision_cache), std::move(GetClientMode)),
        Spool::Create([spool_log_path UTF8String], spool_dir_size_threshold,
                      spool_file_size_threshold, spool_flush_timeout_ms));
    default: LOGE(@"Invalid log type: %ld", log_type); return nullptr;
  }
}

Logger::Logger(std::shared_ptr<serializers::Serializer> serializer,
               std::shared_ptr<writers::Writer> writer)
    : serializer_(std::move(serializer)), writer_(std::move(writer)) {}

void Logger::Log(std::shared_ptr<EnrichedMessage> msg) {
  writer_->Write(serializer_->SerializeMessage(std::move(msg)));
}

void Logger::LogAllowlist(const Message &msg, const std::string_view hash) {
  writer_->Write(serializer_->SerializeAllowlist(msg, hash));
}

void Logger::LogBundleHashingEvents(NSArray<SNTStoredEvent *> *events) {
  for (SNTStoredEvent *se in events) {
    writer_->Write(serializer_->SerializeBundleHashingEvent(se));
  }
}

void Logger::LogDiskAppeared(NSDictionary *props) {
  writer_->Write(serializer_->SerializeDiskAppeared(props));
}

void Logger::LogDiskDisappeared(NSDictionary *props) {
  writer_->Write(serializer_->SerializeDiskDisappeared(props));
}

void Logger::LogFileAccess(
  const std::string &policy_version, const std::string &policy_name,
  const santa::santad::event_providers::endpoint_security::Message &msg,
  const santa::santad::event_providers::endpoint_security::EnrichedProcess &enriched_process,
  const std::string &target, FileAccessPolicyDecision decision) {
  writer_->Write(serializer_->SerializeFileAccess(policy_version, policy_name, msg,
                                                  enriched_process, target, decision));
}

void Logger::Flush() {
  writer_->Flush();
}

}  // namespace santa::santad::logs::endpoint_security
