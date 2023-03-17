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

#include "Source/santad/EventProviders/RateLimiter.h"

#include "Source/common/BranchPrediction.h"
#include "Source/common/SystemResources.h"

namespace santa::santad::event_providers {

std::shared_ptr<RateLimiter> RateLimiter::Create(uint16_t max_qps, NSTimeInterval reset_duration) {
  return std::make_shared<RateLimiter>(max_qps, reset_duration);
}

RateLimiter::RateLimiter(uint16_t max_qps, NSTimeInterval reset_duration)
    : max_log_count_total_(reset_duration * max_qps),
      reset_mach_time_(0),
      reset_duration_ns_(reset_duration * NSEC_PER_SEC) {
  q_ = dispatch_queue_create(
    "com.google.santa.daemon.rate_limiter",
    dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                            QOS_CLASS_USER_INTERACTIVE, 0));
}

void RateLimiter::TryResetLocked(uint64_t cur_mach_time) {
  if (cur_mach_time > reset_mach_time_) {
    log_count_total_ = 0;
    reset_mach_time_ = AddNanosecondsToMachTime(reset_duration_ns_, cur_mach_time);
  }
}

RateLimiter::Decision RateLimiter::Decide(uint64_t cur_mach_time) {
  __block RateLimiter::Decision decision;

  dispatch_sync(q_, ^{
    TryResetLocked(cur_mach_time);

    ++log_count_total_;

    if (unlikely(log_count_total_ > max_log_count_total_)) {
      decision = Decision::kRateLimited;
    } else {
      decision = RateLimiter::Decision::kAllowed;
    }
  });

  return decision;
}

}  // namespace santa::santad::event_providers
