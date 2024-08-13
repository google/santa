/// Copyright 2023 Google LLC
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

#ifndef SANTA__COMMON__STRING_H
#define SANTA__COMMON__STRING_H

#include <EndpointSecurity/ESTypes.h>
#include <Foundation/Foundation.h>

#include <optional>
#include <string>
#include <string_view>

namespace santa {

static inline std::string_view NSStringToUTF8StringView(NSString *str) {
  return std::string_view(str.UTF8String, [str lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
}

static inline std::string NSStringToUTF8String(NSString *str) {
  return std::string(str.UTF8String, [str lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
}

static inline NSString *StringToNSString(const std::string &str) {
  return [NSString stringWithUTF8String:str.c_str()];
}

static inline NSString *StringToNSString(const char *str) {
  return [NSString stringWithUTF8String:str];
}

static inline NSString *OptionalStringToNSString(const std::optional<std::string> &optional_str) {
  std::string str = optional_str.value_or("");
  if (str.length() == 0) {
    return nil;
  } else {
    return StringToNSString(str);
  }
}

static inline std::string_view StringTokenToStringView(es_string_token_t es_str) {
  return std::string_view(es_str.data, es_str.length);
}

}  // namespace santa

#endif
