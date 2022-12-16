#include <cstddef>
#include <cstdint>

extern void FuzzOne(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzOne(data, size);
  return 0;
}
