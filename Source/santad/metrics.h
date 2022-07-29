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

#ifndef SANTA__SANTAD__METRICS_H
#define SANTA__SANTAD__METRICS_H

#include <dispatch/dispatch.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#include <memory>

namespace santa::santad {

class Metrics : public std::enable_shared_from_this<Metrics> {
public:
  static std::shared_ptr<Metrics> Create(uint64_t interval);

  Metrics(MOLXPCConnection* metrics_connection,
          dispatch_queue_t q,
          dispatch_source_t timer_source,
          uint64_t interval);

  ~Metrics();

  void StartPoll();
  void StopPoll();

private:
  MOLXPCConnection *metrics_connection_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  uint64_t interval_;
  // Tracks whether or not the timer_source should be running.
  // This helps manage dispatch source state to ensure the source is not
  // suspended, resumed, or cancelled while in an improper state.
  bool running_;
};

} // namespace santa::santad

#endif
