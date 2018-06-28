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

/*
  This test will attempt to connect to the driver multiple times to make
  sure that it doesn't cause crashes
*/

#import "SNTDriverManager.h"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <vector>
#include <atomic>

std::mutex mutex;
std::condition_variable condVariable;
std::atomic_bool terminate(false);

void SignalHandler(int signalId) {
  std::lock_guard<std::mutex> lock(mutex);
  terminate = true;

  condVariable.notify_one();
}

void Thread() {
  while (!terminate) {
    SNTDriverManager *driverManager = [[SNTDriverManager alloc] init];
    if (driverManager != nullptr) {
      std::cout << ".";
    }
  }
}

int main(int argc, const char *argv[]) {
  signal(SIGINT, &SignalHandler);

  std::vector<std::thread> thread_list;
  for (auto i = 0U; i < 1U; i++) {
    thread_list.emplace_back(Thread);
  }
  
  std::unique_lock<std::mutex> lock(mutex);
  condVariable.wait(
    lock,
    []{
      return terminate.load();
    }
  );

  for (auto &t : thread_list) {
    t.join();
  }

  return 0;
}
