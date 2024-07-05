/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_MOCKLOGGER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_MOCKLOGGER_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

class MockLogger : public santa::Logger {
 public:
  using Logger::Logger;

  MockLogger() : Logger(nullptr, nullptr) {}

  MOCK_METHOD(
      void, LogFileAccess,
      (const std::string &policy_version, const std::string &policy_name,
       const santa::santad::event_providers::endpoint_security::Message &msg,
       const santa::santad::event_providers::endpoint_security::EnrichedProcess
           &enriched_process,
       const std::string &target, FileAccessPolicyDecision decision));
};

#endif
