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
