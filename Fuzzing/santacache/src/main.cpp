/// Copyright 2018 Google Inc. All rights reserved.
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

#include <SantaCache.h>

#include <iostream>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  static SantaCache<uint64_t, uint64_t> decision_cache(5000, 2);

  std::uint64_t fields[2] = {};

  if (size > 16) {
    std::cout << "Invalid size! Start with -max_len=16\n";
    return 1;
  }

  std::memcpy(fields, data, size);

  decision_cache.set(fields[0], fields[1]);
  auto returned_value = decision_cache.get(fields[0]);

  if (returned_value != fields[1]) {
    std::cout << fields[0] << ", " << fields[1] << " -> " << returned_value << "\n";
    return 1;
  }

  return 0;
}
