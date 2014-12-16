/// Copyright 2014 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTA_DRIVER__SANTADECISIONMANAGER_H
#define SANTA__SANTA_DRIVER__SANTADECISIONMANAGER_H

#include <IOKit/IOLib.h>
#include <IOKit/IOSharedDataQueue.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/crypto/sha1.h>
#include <sys/kauth.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include "SantaMessage.h"
#include "SNTKernelCommon.h"
#include "SNTLogging.h"

/// The maximum number of milliseconds a cached deny message should be
/// considered valid.
const uint64_t kMaxDenyCacheTimeMilliseconds = 500;

/// The maximum number of milliseconds a cached allow message should be
/// considered valid.
const uint64_t kMaxAllowCacheTimeMilliseconds = 1000 * 60 * 60 * 24;

/// While waiting for a response from the daemon, this is the number of
/// milliseconds to sleep for before checking the cache for a response.
const int kRequestLoopSleepMilliseconds = 10;

/// While waiting for a response from the daemon, this is the maximum number
/// of loops to wait before sending the request again.
const int kMaxRequestLoops = 50;

/// Maximum number of entries in the in-kernel cache.
const int kMaxCacheSize = 10000;

/// SantaDecisionManager is responsible for intercepting Vnode execute actions
/// and responding to the request appropriately.
///
/// Documentation on the Kauth parts can be found here:
/// https://developer.apple.com/library/mac/technotes/tn2127/_index.html
class SantaDecisionManager : public OSObject {
  OSDeclareDefaultStructors(SantaDecisionManager);

 public:
  // Convenience constructor
  // Queue remains owned by caller but must exist for lifetime of
  // SantaDecisionManager instance.
  static SantaDecisionManager *WithQueueAndPID(
      IOSharedDataQueue *queue, pid_t pid);

  bool InitWithQueueAndPID(IOSharedDataQueue *queue, pid_t pid);
  void free();

  // Decision Fetching / Daemon Communication
  bool PostToQueue(santa_message_t);
  santa_action_t FetchDecision(const kauth_cred_t credential,
                               const vfs_context_t vfs_context,
                               const vnode_t vnode);

  // Hash calculation
  bool CalculateSHA1ForVnode(const kauth_cred_t credential,
                             const vfs_context_t context,
                             const vnode_t vnode,
                             char *out);

  // Vnode ID string
  uint64_t GetVnodeIDForVnode(const vfs_context_t context, const vnode_t vp);

  // Cache management
  void AddToCache(const char *identifier,
                  const santa_action_t decision,
                  const uint64_t microsecs);
  void CacheCheck(const char *identifier);
  uint64_t CacheCount();
  void ClearCache();
  santa_action_t GetFromCache(const char *identifier);

  // Listener invocation management
  SInt32 GetListenerInvocations();
  void IncrementListenerInvocations();
  void DecrementListenerInvocations();

  // Owning PID comparison
  bool MatchesOwningPID(const pid_t other_pid);

  // Returns the current system uptime in microseconds
  uint64_t GetCurrentUptime();

  // Starting and stopping the listener
  kern_return_t StartListener();
  kern_return_t StopListener();

 private:
  OSDictionary *cached_decisions_;
  IORWLock *cached_decisions_lock_;

  IOSharedDataQueue *dataqueue_;
  IORWLock *dataqueue_lock_;

  SInt32 listener_invocations_;

  pid_t owning_pid_;
  proc_t owning_proc_;

  kauth_listener_t vnode_listener_;
  kauth_listener_t process_listener_;
};

extern "C" {
  /// The callback function for the Vnode scope
  /// @param actor's credentials
  /// @param data that was passed when the listener was registered
  /// @param action that was requested
  /// @param VFS context
  /// @param Vnode being operated on
  /// @param Parent Vnode. May be NULL.
  /// @param Pointer to an errno-style error.
  extern int vnode_scope_callback(kauth_cred_t credential,
                                  void *idata,
                                  kauth_action_t action,
                                  uintptr_t arg0,
                                  uintptr_t arg1,
                                  uintptr_t arg2,
                                  uintptr_t arg3);

  /// The callback function for the Process scope
  /// @param actor's credentials
  /// @param data that was passed when the listener was registered
  /// @param action that was requested (KAUTH_PROCESS_{CANTRACE,CANSIGNAL})
  /// @param target process
  /// @param Pointer to an errno-style error.
  /// @param unused
  /// @param unused
  extern int process_scope_callback(kauth_cred_t credential,
                                    void *idata,
                                    kauth_action_t action,
                                    uintptr_t arg0,
                                    uintptr_t arg1,
                                    uintptr_t arg2,
                                    uintptr_t arg3);
}  // extern C

#endif  // SANTA__SANTA_DRIVER__SANTADECISIONMANAGER_H
