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

#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"

namespace santa::santad::logs::endpoint_security::serializers {

SanitizableString::SanitizableString(const es_file_t *file)
    : data_(file->path.data), length_(file->path.length) {}

SanitizableString::SanitizableString(const es_string_token_t &tok)
    : data_(tok.data), length_(tok.length) {}

SanitizableString::SanitizableString(NSString *str)
    : data_([str UTF8String]), length_([str length]) {}

SanitizableString::SanitizableString(const char *str, size_t len) : data_(str), length_(len) {}

std::string_view SanitizableString::String() const {
  return std::string_view(data_, length_);
}

std::string_view SanitizableString::Sanitized() const {
  if (!sanitized_) {
    sanitized_ = true;
    sanitized_string_ = SanitizeString(data_, length_);
  }

  if (sanitized_string_.has_value()) {
    return sanitized_string_.value();
  } else {
    if (data_) {
      return std::string_view(data_, length_);
    } else {
      return "";
    }
  }
}

std::ostream &operator<<(std::ostream &ss, const SanitizableString &sani_string) {
  ss << sani_string.Sanitized();
  return ss;
}

std::optional<std::string> SanitizableString::SanitizeString(const char *str) {
  return SanitizeString(str, str ? strlen(str) : 0);
}

std::optional<std::string> SanitizableString::SanitizeString(const char *str, size_t length) {
  size_t strOffset = 0;
  char c = 0;
  std::string buf;
  bool reservedStringSpace = false;

  if (!str) {
    return std::nullopt;
  }

  if (length < 1) {
    return std::nullopt;
  }

  // Loop through the string one character at a time, looking for the characters
  // we want to remove.
  for (const char *p = str; (c = *p) != 0; ++p) {
    if (c == '|' || c == '\n' || c == '\r') {
      if (!reservedStringSpace) {
        buf.reserve(length * 6);
        reservedStringSpace = true;
      }

      // Copy from the last offset up to the character we just found into the buffer
      ptrdiff_t diff = p - str;
      buf.append(str + strOffset, diff - strOffset);

      // Update the buffer and string offsets
      strOffset = diff + 1;

      // Replace the found character and advance the buffer offset
      switch (c) {
        case '|': buf.append("<pipe>"); break;
        case '\n': buf.append("\\n"); break;
        case '\r': buf.append("\\r"); break;
      }
    }
  }

  if (strOffset > 0 && strOffset < length) {
    // Copy any characters from the last match to the end of the string into the buffer.
    buf.append(str + strOffset, length - strOffset);
  }

  if (reservedStringSpace) {
    return buf;
  }

  return std::nullopt;
}

}  // namespace santa::santad::logs::endpoint_security::serializers
