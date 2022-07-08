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
#include "Source/common/SNTStoredEvent.h"

using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;

namespace santa::santad::logs::endpoint_security {

void Logger::Log(std::shared_ptr<EnrichedMessage> msg) {
  writer_->Write(serializer_->SerializeMessage(std::move(msg)));
}

void Logger::LogAllowlist(const Message& msg, const std::string_view hash) {
  writer_->Write(serializer_->SerializeAllowlist(msg, hash));
}

void Logger::LogBundleHashingEvents(NSArray<SNTStoredEvent*> *events) {
  for (SNTStoredEvent *se in events) {
    writer_->Write(serializer_->SerializeBundleHashingEvent(se));
  }
}

void Logger::LogDiskAppeared(NSDictionary* props) {
  writer_->Write(serializer_->SerializeDiskAppeared(props));
}

void Logger::LogDiskDisappeared(NSDictionary* props) {
  writer_->Write(serializer_->SerializeDiskDisappeared(props));
}

} // namespace santa::santad::logs::endpoint_security
