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

#include <CommonCrypto/CommonDigest.h>
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

static inline NSString *SHA1DigestToNSString(const unsigned char digest[CC_SHA1_DIGEST_LENGTH]) {
  return [[NSString alloc]
    initWithFormat:
      @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
      digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
      digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15],
      digest[16], digest[17], digest[18], digest[19]];
}

static inline NSString *SHA256DigestToNSString(
  const unsigned char digest[CC_SHA256_DIGEST_LENGTH]) {
  return [[NSString alloc]
    initWithFormat:@"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                   digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                   digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13],
                   digest[14], digest[15], digest[16], digest[17], digest[18], digest[19],
                   digest[20], digest[21], digest[22], digest[23], digest[24], digest[25],
                   digest[26], digest[27], digest[28], digest[29], digest[30], digest[31]];
}

}  // namespace santa

#endif
