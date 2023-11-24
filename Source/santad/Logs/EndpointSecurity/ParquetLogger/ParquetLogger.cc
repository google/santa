#include "ParquetLogger.h"

extern "C" {
extern bool parquet2_1337_bloom_filter_contains(int64_t x);
}

bool FilterContains(int64_t x) {
    return parquet2_1337_bloom_filter_contains(x);
}
