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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_WRITER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_WRITER_H

#include <vector>

namespace santa::santad::logs::endpoint_security::writers {

class Writer {
public:
  virtual ~Writer() = default;

  virtual void Write(const std::vector<uint8_t> &bytes) = 0;
};

} // namespace santa::santad::logs::endpoint_security::writers

#endif
