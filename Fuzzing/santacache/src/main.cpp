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
