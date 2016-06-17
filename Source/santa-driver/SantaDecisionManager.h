/// Copyright 2015 Google Inc. All rights reserved.
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

#include <IOKit/IODataQueueShared.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOSharedDataQueue.h>
#include <libkern/c++/OSDictionary.h>
#include <sys/kauth.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include "SNTKernelCommon.h"
#include "SNTLogging.h"
#include "SantaCachedDecision.h"
#include "SantaPIDAndPPID.h"

///
///  SantaDecisionManager is responsible for intercepting Vnode execute actions
///  and responding to the request appropriately.
///
///  Documentation on the Kauth parts can be found here:
///  https://developer.apple.com/library/mac/technotes/tn2127/_index.html
///
class SantaDecisionManager : public OSObject {
  OSDeclareDefaultStructors(SantaDecisionManager);

 public:
  ///  Used for initialization after instantiation. Required because
  ///  constructors cannot throw inside kernel-space.
  bool init() override;

  ///  Called automatically when retain count drops to 0.
  void free() override;

  ///  Called by SantaDriverClient during connection to provide the shared
  ///  dataqueue memory to the client.
  IOMemoryDescriptor *GetDecisionMemoryDescriptor() const;
  IOMemoryDescriptor *GetLogMemoryDescriptor() const;

  ///  Called by SantaDriverClient when a client connects to the decision queue,
  ///  providing the pid of the client process.
  void ConnectClient(pid_t pid);

  ///  Called by SantaDriverClient when a client disconnects
  void DisconnectClient(bool itDied = false);

  ///  Returns whether a client is currently connected or not.
  bool ClientConnected() const;

  ///  Sets the Mach port for notifying the decision queue.
  void SetDecisionPort(mach_port_t port);

  ///  Sets the Mach port for notifying the log queue.
  void SetLogPort(mach_port_t port);

  ///  Starts the kauth listeners.
  kern_return_t StartListener();

  ///  Stops the kauth listeners. After stopping new callback requests,
  ///  waits until all current invocations have finished before clearing the
  ///  cache and returning.
  kern_return_t StopListener();

  ///  Adds a decision to the cache, with a timestamp.
  void AddToCache(const char *identifier,
                  const santa_action_t decision,
                  const uint64_t microsecs = GetCurrentUptime());

  ///  Checks to see if a given identifier is in the cache and removes it.
  void CacheCheck(const char *identifier);

  ///  Returns the number of entries in the cache.
  uint64_t CacheCount() const;

  ///  Clears the cache.
  void ClearCache();
  
  /// Checks for VnodeID in the cache. Returns true if the VnodeID exists.
  bool CheckCache(uint64_t vnode_id);

  ///  Increments the count of active callbacks pending.
  void IncrementListenerInvocations();

  ///  Decrements the count of active callbacks pending.
  void DecrementListenerInvocations();

  ///
  ///  Vnode Callback
  ///  @param cred The kauth credential for this request.
  ///  @param ctx The VFS context for this request.
  ///  @param vp The Vnode for this request.
  ///  @param errno A pointer to return an errno style error.
  ///  @return int A valid KAUTH_RESULT_*.
  ///
  int VnodeCallback(const kauth_cred_t cred, const vfs_context_t ctx,
                    const vnode_t vp, int *errno);
  ///
  ///  FileOp Callback
  ///  @param action The performed action
  ///  @param vp The Vnode for this request. May be nullptr.
  ///  @param path The path being operated on.
  ///  @param new_path The target path for moves and links.
  ///
  void FileOpCallback(kauth_action_t action, const vnode_t vp,
                      const char *path, const char *new_path);

 protected:
  ///
  ///  The maximum number of milliseconds a cached deny message should be
  ///  considered valid.
  ///
  static const uint64_t kMaxDenyCacheTimeMilliseconds = 500;

  ///
  ///  The maximum number of milliseconds a cached allow message should be
  ///  considered valid.
  ///
  static const uint64_t kMaxAllowCacheTimeMilliseconds = 1000 * 60 * 60 * 24;

  ///
  ///  While waiting for a response from the daemon, this is the number of
  ///  milliseconds to sleep for before checking the cache for a response.
  ///
  static const uint32_t kRequestLoopSleepMilliseconds = 10;

  ///
  ///  Maximum number of entries in the in-kernel cache.
  ///
  static const uint32_t kMaxCacheSize = 10000;

  ///
  ///  Maximum number of PostToDecisionQueue failures to allow.
  ///
  static const uint32_t kMaxDecisionQueueFailures = 10;

  ///
  ///  The maximum number of messages can be kept in
  ///  the decision data queue at any time.
  ///
  static const uint32_t kMaxDecisionQueueEvents = 512;

  ///
  ///  The maximum number of messages can be kept
  ///  in the logging data queue at any time.
  ///
  static const uint32_t kMaxLogQueueEvents = 1024;

  ///  Fetches a response from the cache, first checking to see if the
  ///  entry has expired.
  santa_action_t GetFromCache(const char *identifier);

  ///  Fetches a response from the daemon. Handles both daemon death
  ///  and failure to post messages to the daemon.
  ///
  ///  @param message The message to send to the daemon
  ///  @param identifier The vnode ID string for this request
  ///  @return santa_action_t The response for this request
  ///
  santa_action_t GetFromDaemon(santa_message_t *message,
                               const char *identifier);

  ///
  ///  Fetches an execution decision for a file, first using the cache and then
  ///  by sending a message to the daemon and waiting until a response arrives.
  ///  If a daemon isn't connected, will allow execution and cache, logging
  ///  the path to the executed file.
  ///
  ///  @param cred The credential for this request.
  ///  @param vp The Vnode for this request.
  ///  @param vnode_id The ID for this vnode.
  ///  @param vnode_id_str A string representation of the above ID.
  ///
  santa_action_t FetchDecision(const kauth_cred_t cred,
                               const vnode_t vp,
                               const uint64_t vnode_id,
                               const char *vnode_id_str);

  ///
  ///  Posts the requested message to the decision data queue.
  ///
  ///  @param message The message to send
  ///  @return bool true if sending was successful.
  ///
  bool PostToDecisionQueue(santa_message_t *message);

  ///
  ///  Posts the requested message to the logging data queue.
  ///
  ///  @param message The message to send
  ///  @return bool true if sending was successful.
  ///
  bool PostToLogQueue(santa_message_t *message);

  ///
  ///  Fetches the vnode_id for a given vnode.
  ///
  ///  @param ctx The VFS context to use.
  ///  @param vp The Vnode to get the ID for
  ///  @return uint64_t The Vnode ID as a 64-bit unsigned int.
  ///
  static inline uint64_t GetVnodeIDForVnode(const vfs_context_t ctx,
                                            const vnode_t vp) {
    struct vnode_attr vap;
    VATTR_INIT(&vap);
    VATTR_WANTED(&vap, va_fsid);
    VATTR_WANTED(&vap, va_fileid);
    vnode_getattr(vp, &vap, ctx);
    return (((uint64_t)vap.va_fsid << 32) | vap.va_fileid);
  }

  ///
  ///  Creates a new santa_message_t with some fields pre-filled.
  ///  @param credential The kauth_cred_t for this action, if available.
  ///         If nullptr, will get the credential for the current process.
  ///
  static inline santa_message_t *NewMessage(kauth_cred_t credential) {
    bool should_release = false;
    if (credential == nullptr) {
      credential = kauth_cred_get_with_ref();
      should_release = true;
    }

    auto message = new santa_message_t;
    message->uid = kauth_cred_getuid(credential);
    message->gid = kauth_cred_getgid(credential);
    message->pid = proc_selfpid();
    message->ppid = proc_selfppid();

    if (should_release) {
      kauth_cred_unref(&credential);
    }
    
    return message;
  }

  ///
  ///  Returns the current system uptime in microseconds
  ///
  static inline uint64_t GetCurrentUptime() {
    clock_sec_t sec;
    clock_usec_t usec;
    clock_get_system_microtime(&sec, &usec);
    return (uint64_t)((sec * 1000000) + usec);
  }

 private:
  lck_grp_t *sdm_lock_grp_;
  lck_grp_attr_t *sdm_lock_grp_attr_;

  lck_attr_t *sdm_lock_attr_;
  lck_rw_t *cached_decisions_lock_;
  lck_mtx_t *decision_dataqueue_lock_;
  lck_mtx_t *log_dataqueue_lock_;
  lck_rw_t *vnode_pid_map_lock_;

  OSDictionary *cached_decisions_;
  OSDictionary *vnode_pid_map_;

  IOSharedDataQueue *decision_dataqueue_;
  IOSharedDataQueue *log_dataqueue_;
  int32_t failed_decision_queue_requests_;
  int32_t failed_log_queue_requests_;

  int32_t listener_invocations_;

  pid_t client_pid_;

  kauth_listener_t vnode_listener_;
  kauth_listener_t fileop_listener_;
};

///
///  The kauth callback function for the Vnode scope
///  @param actor's credentials
///  @param data that was passed when the listener was registered
///  @param action that was requested
///  @param VFS context
///  @param Vnode being operated on
///  @param Parent Vnode. May be nullptr.
///  @param Pointer to an errno-style error.
///
extern "C" int vnode_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

///
///  The kauth callback function for the FileOp scope
///  @param actor's credentials
///  @param data that was passed when the listener was registered
///  @param action that was requested
///  @param depends on action, usually the vnode ref.
///  @param depends on action.
///  @param depends on action, usually 0.
///  @param depends on action, usually 0.
///
extern "C" int fileop_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

#endif  // SANTA__SANTA_DRIVER__SANTADECISIONMANAGER_H
