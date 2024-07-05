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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_RATELIMITER_H
#define SANTA__SANTAD__EVENTPROVIDERS_RATELIMITER_H

#import <Foundation/Foundation.h>

#include <atomic>
#include <memory>

#include "Source/santad/Metrics.h"

// Forward declarations
namespace santa {
class RateLimiterPeer;
}  // namespace santa

namespace santa {

// Very basic rate limiting infrastructure.
// Currently only handles X events per duration.
//
// TODO(mlw): Support changing QPS via config
// TODO(mlw): Support per-rule QPS
// TODO(mlw): Consider adding sliding window support
class RateLimiter {
 public:
  // Factory
  static std::shared_ptr<RateLimiter> Create(
      std::shared_ptr<santa::Metrics> metrics, santa::Processor processor,
      uint16_t max_qps, NSTimeInterval reset_duration = kDefaultResetDuration);

  RateLimiter(std::shared_ptr<santa::Metrics> metrics,
              santa::Processor processor, uint16_t max_qps,
              NSTimeInterval reset_duration);

  enum class Decision {
    kRateLimited = 0,
    kAllowed,
  };

  Decision Decide(uint64_t cur_mach_time);

  friend class santa::RateLimiterPeer;

 private:
  bool ShouldRateLimitLocked();
  size_t EventsRateLimitedLocked();
  void TryResetLocked(uint64_t cur_mach_time);

  static constexpr NSTimeInterval kDefaultResetDuration = 15.0;

  std::shared_ptr<santa::Metrics> metrics_;
  santa::Processor processor_;
  size_t log_count_total_ = 0;
  size_t max_log_count_total_;
  uint64_t reset_mach_time_;
  uint64_t reset_duration_ns_;
  dispatch_queue_t q_;
};

}  // namespace santa

#endif
