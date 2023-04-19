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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_SANITIZABLESTRING_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_SANITIZABLESTRING_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>

#include <optional>
#include <sstream>
#include <string>

namespace santa::santad::logs::endpoint_security::serializers {

// Small helper class that will sanitize a given string, but will only use new
// memory if the string required sanitization. If the string is already
// sanitized, this class only uses the given buffers.
class SanitizableString {
 public:
  SanitizableString(const es_file_t *file);
  SanitizableString(const es_string_token_t &tok);
  SanitizableString(const char *str, size_t len);
  SanitizableString(NSString *str);

  SanitizableString(SanitizableString &&other) = delete;
  SanitizableString(const SanitizableString &other) = delete;
  SanitizableString &operator=(const SanitizableString &rhs) = delete;
  SanitizableString &operator=(SanitizableString &&rhs) = delete;

  // Return the original, unsanitized string
  std::string_view String() const;

  // Return the sanitized string
  std::string_view Sanitized() const;

  static std::optional<std::string> SanitizeString(const char *str);
  static std::optional<std::string> SanitizeString(const char *str, size_t length);

  friend std::ostream &operator<<(std::ostream &ss, const SanitizableString &sani_string);

 private:
  std::string_view data_;
  mutable bool sanitized_ = false;
  mutable std::optional<std::string> sanitized_string_;
};

}  // namespace santa::santad::logs::endpoint_security::serializers

#endif
