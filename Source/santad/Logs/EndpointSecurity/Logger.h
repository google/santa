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

#import "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#import "Source/santad/EventProviders/EndpointSecurity/Message.h"
#import "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

@class SNTStoredEvent;

namespace santa::santad::logs::endpoint_security {

class Logger {
public:
  Logger(std::unique_ptr<serializers::Serializer> serializer,
                 std::unique_ptr<writers::Writer> writer)
      : serializer_(std::move(serializer)), writer_(std::move(writer)) {}

  void Log(
      std::unique_ptr<santa::santad::event_providers::endpoint_security::EnrichedMessage> msg);

  void LogAllowList(
      const santa::santad::event_providers::endpoint_security::Message& msg,
      const std::string_view hash);

  void LogBundleHashingEvents(NSArray<SNTStoredEvent*>* events);

  void LogDiskAppeared(NSDictionary* props);
  void LogDiskDisappeared(NSDictionary* props);

private:
  std::unique_ptr<serializers::Serializer> serializer_;
  std::unique_ptr<writers::Writer> writer_;
};

} // namespace santa::santad::logs::endpoint_security

#endif
