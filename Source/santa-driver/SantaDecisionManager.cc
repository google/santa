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

#include "SantaDecisionManager.h"

// This is a made-up KAUTH_FILEOP constant which represents a
// KAUTH_VNODE_WRITE_DATA event that gets passed to SantaDecisionManager's
// FileOpCallback method.  The KAUTH_FILEOP_* constants are defined in
// sys/kauth.h and run from 1--7.  KAUTH_VNODE_WRITE_DATA is already defined as
// 4 so it overlaps with the other KAUTH_FILEOP_* constants and can't be used.
// We define KAUTH_FILEOP_WRITE as something much greater than 7.
#define KAUTH_FILEOP_WRITE 100

#define super OSObject
OSDefineMetaClassAndStructors(SantaDecisionManager, OSObject);

#pragma mark Object Lifecycle

template<> uint64_t SantaCacheHasher<santa_vnode_id_t>(santa_vnode_id_t const& s) {
  return (SantaCacheHasher<uint64_t>(s.fsid) << 1) ^ SantaCacheHasher<uint64_t>(s.fileid);
}

bool SantaDecisionManager::init() {
  if (!super::init()) return false;

  sdm_lock_grp_attr_ = lck_grp_attr_alloc_init();
  sdm_lock_grp_ = lck_grp_alloc_init("santa-locks", sdm_lock_grp_attr_);
  sdm_lock_attr_ = lck_attr_alloc_init();

  decision_dataqueue_lock_ = lck_mtx_alloc_init(sdm_lock_grp_, sdm_lock_attr_);
  log_dataqueue_lock_ = lck_mtx_alloc_init(sdm_lock_grp_, sdm_lock_attr_);

  decision_cache_ = new SantaCache<santa_vnode_id_t, uint64_t>(10000, 2);
  vnode_pid_map_ = new SantaCache<santa_vnode_id_t, uint64_t>(2000, 5);
  compiler_pid_set_ = new SantaCache<pid_t, pid_t>(500, 5);

  decision_dataqueue_ = IOSharedDataQueue::withEntries(
      kMaxDecisionQueueEvents, sizeof(santa_message_t));
  if (!decision_dataqueue_) return kIOReturnNoMemory;

  log_dataqueue_ = IOSharedDataQueue::withEntries(
      kMaxLogQueueEvents, sizeof(santa_message_t));
  if (!log_dataqueue_) return kIOReturnNoMemory;

  client_pid_ = 0;

  return true;
}

void SantaDecisionManager::free() {
  delete decision_cache_;
  delete vnode_pid_map_;

  StopPidMonitorThreads();

  if (decision_dataqueue_lock_) {
    lck_mtx_free(decision_dataqueue_lock_, sdm_lock_grp_);
    decision_dataqueue_lock_ = nullptr;
  }

  if (log_dataqueue_lock_) {
    lck_mtx_free(log_dataqueue_lock_, sdm_lock_grp_);
    log_dataqueue_lock_ = nullptr;
  }

  if (sdm_lock_attr_) {
    lck_attr_free(sdm_lock_attr_);
    sdm_lock_attr_ = nullptr;
  }

  if (sdm_lock_grp_) {
    lck_grp_free(sdm_lock_grp_);
    sdm_lock_grp_ = nullptr;
  }

  if (sdm_lock_grp_attr_) {
    lck_grp_attr_free(sdm_lock_grp_attr_);
    sdm_lock_grp_attr_ = nullptr;
  }

  OSSafeReleaseNULL(decision_dataqueue_);
  OSSafeReleaseNULL(log_dataqueue_);

  super::free();
}

#pragma mark Client Management

void SantaDecisionManager::ConnectClient(pid_t pid) {
  if (!pid) return;

  client_pid_ = pid;

  // Any decisions made while the daemon wasn't
  // connected should be cleared
  ClearCache();

  failed_decision_queue_requests_ = 0;
  failed_log_queue_requests_ = 0;
}

void SantaDecisionManager::DisconnectClient(bool itDied, pid_t pid) {
  if (client_pid_ == 0 || (pid > 0 && pid != client_pid_)) return;
  client_pid_ = 0;

  // Ask santad to shutdown, in case it's running.
  if (!itDied) {
    auto message = new santa_message_t;
    message->action = ACTION_REQUEST_SHUTDOWN;
    PostToDecisionQueue(message);
    delete message;
    decision_dataqueue_->setNotificationPort(nullptr);
  } else {
    // If the client died, reset the data queues so when it reconnects
    // it doesn't get swamped straight away.
    lck_mtx_lock(decision_dataqueue_lock_);
    decision_dataqueue_->release();
    decision_dataqueue_ = IOSharedDataQueue::withEntries(
        kMaxDecisionQueueEvents, sizeof(santa_message_t));
    lck_mtx_unlock(decision_dataqueue_lock_);

    lck_mtx_lock(log_dataqueue_lock_);
    log_dataqueue_->release();
    log_dataqueue_ = IOSharedDataQueue::withEntries(
        kMaxLogQueueEvents, sizeof(santa_message_t));
    lck_mtx_unlock(log_dataqueue_lock_);
  }
}

bool SantaDecisionManager::ClientConnected() const {
  if (client_pid_ <= 0) return false;
  auto p = proc_find(client_pid_);
  auto is_exiting = false;
  if (p) {
    is_exiting = proc_exiting(p);
    proc_rele(p);
  }
  return (client_pid_ > 0 && !is_exiting);
}

void SantaDecisionManager::SetDecisionPort(mach_port_t port) {
  lck_mtx_lock(decision_dataqueue_lock_);
  decision_dataqueue_->setNotificationPort(port);
  lck_mtx_unlock(decision_dataqueue_lock_);
}

void SantaDecisionManager::SetLogPort(mach_port_t port) {
  lck_mtx_lock(log_dataqueue_lock_);
  log_dataqueue_->setNotificationPort(port);
  lck_mtx_unlock(log_dataqueue_lock_);
}

IOMemoryDescriptor *SantaDecisionManager::GetDecisionMemoryDescriptor() const {
  return decision_dataqueue_->getMemoryDescriptor();
}

IOMemoryDescriptor *SantaDecisionManager::GetLogMemoryDescriptor() const {
  return log_dataqueue_->getMemoryDescriptor();
}

#pragma mark Listener Control

kern_return_t SantaDecisionManager::StartListener() {
  vnode_listener_ = kauth_listen_scope(
      KAUTH_SCOPE_VNODE, vnode_scope_callback, reinterpret_cast<void *>(this));
  if (!vnode_listener_) return kIOReturnInternalError;

  fileop_listener_ = kauth_listen_scope(
      KAUTH_SCOPE_FILEOP, fileop_scope_callback,
      reinterpret_cast<void *>(this));
  if (!fileop_listener_) return kIOReturnInternalError;

  LOGD("Listeners started.");

  return kIOReturnSuccess;
}

kern_return_t SantaDecisionManager::StopListener() {
  kauth_unlisten_scope(vnode_listener_);
  vnode_listener_ = nullptr;

  kauth_unlisten_scope(fileop_listener_);
  fileop_listener_ = nullptr;

  // Wait for any active invocations to finish before returning
  do {
    IOSleep(5);
  } while (listener_invocations_);

  // Delete any cached decisions
  ClearCache();

  LOGD("Listeners stopped.");

  return kIOReturnSuccess;
}

# pragma mark Monitoring PIDs

// Arguments that are passed to pid_monitor thread.
typedef struct {
  pid_t pid;                  // process to monitor
  SantaDecisionManager *sdm;  // reference to SantaDecisionManager
} pid_monitor_info;

// Function executed in its own thread used to monitor a compiler process for
// termination and then remove the process pid from cache of compiler pids.
static void pid_monitor(void *param, __unused wait_result_t wait_result) {
  pid_monitor_info *info = (pid_monitor_info *)param;
  if (info && info->sdm) {
    uint32_t sleep_time = info->sdm->PidMonitorSleepTimeMilliseconds();
    while (!info->sdm->PidMonitorThreadsShouldExit()) {
      proc_t proc = proc_find(info->pid);
      if (!proc) break;
      proc_rele(proc);
      IOSleep(sleep_time);
    }
    info->sdm->ForgetCompilerPid(info->pid);
    info->sdm->DecrementPidMonitorThreadCount();
  }
  thread_terminate(current_thread());
}

// TODO(nguyenphillip): Look at moving pid monitoring out of SDM entirely,
// maybe by creating a dedicated class to do this that SDM could then query.
void SantaDecisionManager::MonitorCompilerPidForExit(pid_t pid) {
  // Don't start any new threads if compiler_pid_set_ doesn't exist.
  if (!compiler_pid_set_) return;
  auto info = new pid_monitor_info;
  info->pid = pid;
  info->sdm = this;
  thread_t thread = THREAD_NULL;
  IncrementPidMonitorThreadCount();
  if (KERN_SUCCESS != kernel_thread_start(pid_monitor, (void *)info, &thread)) {
    LOGE("couldn't start pid monitor thread");
    DecrementPidMonitorThreadCount();
  }
  thread_deallocate(thread);
}

void SantaDecisionManager::ForgetCompilerPid(pid_t pid) {
  if (compiler_pid_set_) compiler_pid_set_->remove(pid);
}

bool SantaDecisionManager::PidMonitorThreadsShouldExit() const {
  return compiler_pid_set_ == nullptr;
}

bool SantaDecisionManager::StopPidMonitorThreads() {
  // Each pid_monitor thread checks for the existence of compiler_pid_set_.
  // As soon as they see that it's gone, they should terminate and decrement
  // SantaDecisionManager's pid_monitor_thread_count.  When this count decreases
  // to zero all threads have finished.
  auto temp = compiler_pid_set_;
  compiler_pid_set_ = nullptr;
  delete temp;

  // Sleep time between checks starts at 10 ms, but increases to 5 sec after
  // 10 sec have passed without the thread count dropping to 0.
  unsigned int sleep_time_milliseconds = 10;
  unsigned int total_wait_time = 0;

  while (pid_monitor_thread_count_ > 0) {
    if (sleep_time_milliseconds == 10) {
      total_wait_time += sleep_time_milliseconds;
      if (total_wait_time >= 10000) {
        sleep_time_milliseconds = 5000;
        LOGD("Waited %d ms for pid monitor threads to quit, switching sleep"
             "time to %d ms", total_wait_time, sleep_time_milliseconds);
      }
    }
    IOSleep(sleep_time_milliseconds);
  }
  LOGD("Pid monitor threads stopped.");
  return true;
}

uint32_t SantaDecisionManager::PidMonitorSleepTimeMilliseconds() const {
  return kPidMonitorSleepTimeMilliseconds;
}

#pragma mark Cache Management

void SantaDecisionManager::AddToCache(
    santa_vnode_id_t identifier, santa_action_t decision, uint64_t microsecs) {
  switch (decision) {
    case ACTION_REQUEST_BINARY:
      decision_cache_->set(identifier, (uint64_t)ACTION_REQUEST_BINARY << 56, 0);
      break;
    case ACTION_RESPOND_ACK:
      decision_cache_->set(identifier, (uint64_t)ACTION_RESPOND_ACK << 56,
                          ((uint64_t)ACTION_REQUEST_BINARY << 56));
      break;
    case ACTION_RESPOND_ALLOW:
    case ACTION_RESPOND_ALLOW_COMPILER:
    case ACTION_RESPOND_DENY: {
      // Decision is stored in upper 8 bits, timestamp in remaining 56.
      uint64_t val = ((uint64_t)decision << 56) | (microsecs & 0xFFFFFFFFFFFFFF);
      if (!decision_cache_->set(identifier, val, ((uint64_t)ACTION_REQUEST_BINARY << 56))) {
        decision_cache_->set(identifier, val, ((uint64_t)ACTION_RESPOND_ACK << 56));
      }
      break;
    }
    case ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE: {
      // Decision is stored in upper 8 bits, timestamp in remaining 56.
      uint64_t val = ((uint64_t)decision << 56) | (microsecs & 0xFFFFFFFFFFFFFF);
      decision_cache_->set(identifier, val, 0);
      break;
    }
    default:
      break;
  }

  wakeup((void *)identifier.unsafe_simple_id());
}

void SantaDecisionManager::RemoveFromCache(santa_vnode_id_t identifier) {
  if (unlikely(identifier.fsid == 0 && identifier.fileid == 0)) return;
  decision_cache_->remove(identifier);
  wakeup((void *)identifier.unsafe_simple_id());
}

uint64_t SantaDecisionManager::CacheCount() const {
  return decision_cache_->count();
}

void SantaDecisionManager::ClearCache() {
  decision_cache_->clear();
}

void SantaDecisionManager::CacheBucketCount(
    uint16_t *per_bucket_counts, uint16_t *array_size, uint64_t *start_bucket) {
  decision_cache_->bucket_counts(per_bucket_counts, array_size, start_bucket);
}

#pragma mark Decision Fetching

santa_action_t SantaDecisionManager::GetFromCache(santa_vnode_id_t identifier) {
  auto result = ACTION_UNSET;
  uint64_t decision_time = 0;

  uint64_t cache_val = decision_cache_->get(identifier);
  if (cache_val == 0) return result;

  // Decision is stored in upper 8 bits, timestamp in remaining 56.
  result = (santa_action_t)(cache_val >> 56);
  decision_time = (cache_val & ~(0xFF00000000000000));

  if (RESPONSE_VALID(result)) {
    if (result == ACTION_RESPOND_DENY) {
      auto expiry_time = decision_time + (kMaxDenyCacheTimeMilliseconds * 1000);
      if (expiry_time < GetCurrentUptime()) {
        decision_cache_->remove(identifier);
        return ACTION_UNSET;
      }
    }
  }

  return result;
}

santa_action_t SantaDecisionManager::GetFromDaemon(
    santa_message_t *message, santa_vnode_id_t identifier) {
  auto return_action = ACTION_UNSET;

#ifdef DEBUG
  clock_sec_t secs = 0;
  clock_usec_t microsecs = 0;
  clock_get_system_microtime(&secs, &microsecs);
  uint64_t uptime = (secs * 1000000) + microsecs;
#endif

  // Wait for the daemon to respond or die.
  do {
    // Add pending request to cache, to be replaced
    // by daemon with actual response.
    AddToCache(identifier, ACTION_REQUEST_BINARY, 0);

    // Send request to daemon.
    if (!PostToDecisionQueue(message)) {
      LOGE("Failed to queue request for %s.", message->path);
      RemoveFromCache(identifier);
      return ACTION_ERROR;
    }

    // Check the cache every kRequestLoopSleepMilliseconds. Break this loop and send the request
    // again if kRequestCacheChecks is reached. Don't break the loop if the daemon is working on the
    // request, indicated with ACTION_RESPOND_ACK.
    auto cache_check_count = 0;
    do {
      msleep((void *)message->vnode_id.unsafe_simple_id(), NULL, 0, "", &ts_);
      return_action = GetFromCache(identifier);
    } while (ClientConnected() &&
             ((return_action == ACTION_REQUEST_BINARY && ++cache_check_count < kRequestCacheChecks)
             || (return_action == ACTION_RESPOND_ACK)));
  } while (!RESPONSE_VALID(return_action) && ClientConnected());

  // If response is still not valid, the daemon exited
  if (!RESPONSE_VALID(return_action)) {
    LOGE("Daemon process did not respond correctly. Allowing executions "
         "until it comes back. Executable path: %s", message->path);
    RemoveFromCache(identifier);
    return ACTION_ERROR;
  }

#ifdef DEBUG
  clock_get_system_microtime(&secs, &microsecs);
  LOGD("Decision time: %4lldms (%s)",
       (((secs * 1000000) + microsecs) - uptime) / 1000, message->path);
#endif

  return return_action;
}

santa_action_t SantaDecisionManager::FetchDecision(
    const kauth_cred_t cred,
    const vnode_t vp,
    const santa_vnode_id_t vnode_id) {
  while (true) {
    if (!ClientConnected()) return ACTION_RESPOND_ALLOW;

    // Check to see if item is in cache
    auto return_action = GetFromCache(vnode_id);

    // If item was in cache with a valid response, return it.
    // If item is in cache but hasn't received a response yet, sleep for a bit.
    // If item is not in cache, break out of loop to send request to daemon.
    if (RESPONSE_VALID(return_action)) {
      return return_action;
    } else if (return_action == ACTION_REQUEST_BINARY || return_action == ACTION_RESPOND_ACK) {
      // This thread will now sleep for kRequestLoopSleepMilliseconds (1s) or
      // until AddToCache is called, indicating a response has arrived.
      msleep((void *)vnode_id.unsafe_simple_id(), NULL, 0, "", &ts_);
    } else {
      break;
    }
  }

  // Get path
  char path[MAXPATHLEN];
  int name_len = MAXPATHLEN;
  path[MAXPATHLEN - 1] = 0;

  if (vn_getpath(vp, path, &name_len) == ENOSPC) {
    return ACTION_RESPOND_TOOLONG;
  }

  auto message = NewMessage(cred);
  strlcpy(message->path, path, sizeof(message->path));
  message->action = ACTION_REQUEST_BINARY;
  message->vnode_id = vnode_id;
  proc_name(message->ppid, message->pname, sizeof(message->pname));
  auto return_action = GetFromDaemon(message, vnode_id);
  delete message;
  return return_action;
}

#pragma mark Misc

bool SantaDecisionManager::PostToDecisionQueue(santa_message_t *message) {
  lck_mtx_lock(decision_dataqueue_lock_);
  auto kr = decision_dataqueue_->enqueue(message, sizeof(santa_message_t));
  if (!kr) {
    if (++failed_decision_queue_requests_ > kMaxDecisionQueueFailures) {
      LOGE("Failed to queue more than %d decision requests, killing daemon",
           kMaxDecisionQueueFailures);
      proc_signal(client_pid_, SIGKILL);
    }
  }
  lck_mtx_unlock(decision_dataqueue_lock_);
  return kr;
}

bool SantaDecisionManager::PostToLogQueue(santa_message_t *message) {
  lck_mtx_lock(log_dataqueue_lock_);
  auto kr = log_dataqueue_->enqueue(message, sizeof(santa_message_t));
  if (!kr) {
    if (failed_log_queue_requests_++ == 0) {
      LOGW("Dropping log queue messages");
    }
  } else {
    if (failed_log_queue_requests_ > 0) {
      failed_log_queue_requests_--;
    }
  }
  lck_mtx_unlock(log_dataqueue_lock_);
  return kr;
}

#pragma mark Invocation Tracking & PID comparison

void SantaDecisionManager::IncrementListenerInvocations() {
  OSIncrementAtomic(&listener_invocations_);
}

void SantaDecisionManager::DecrementListenerInvocations() {
  OSDecrementAtomic(&listener_invocations_);
}

void SantaDecisionManager::IncrementPidMonitorThreadCount() {
  OSIncrementAtomic(&pid_monitor_thread_count_);
}

void SantaDecisionManager::DecrementPidMonitorThreadCount() {
  OSDecrementAtomic(&pid_monitor_thread_count_);
}

bool SantaDecisionManager::IsCompilerProcess(pid_t pid) {
  for (;;) {
    // Find the parent pid.
    proc_t proc = proc_find(pid);
    if (!proc) return false;
    pid_t ppid = proc_ppid(proc);
    proc_rele(proc);
    // Quit if process is launchd or has no parent.
    if (ppid == 0 || pid == ppid) break;
    pid_t val = compiler_pid_set_->get(pid);
    // If pid was in compiler_pid_set_ then make sure that it has the same
    // parent pid as when it was set.
    if (val) return val == ppid;
    // If pid not in the set, then quit unless we want to check ancestors.
    if (!kCheckCompilerAncestors) break;
    pid = ppid;
  }
  return false;
}

#pragma mark Callbacks

int SantaDecisionManager::VnodeCallback(const kauth_cred_t cred,
                                        const vfs_context_t ctx,
                                        const vnode_t vp,
                                        int *errno) {
  // Get ID for the vnode
  auto vnode_id = GetVnodeIDForVnode(ctx, vp);
  if (vnode_id.fsid == 0 && vnode_id.fileid == 0) return KAUTH_RESULT_DEFER;

  // Fetch decision
  auto returnedAction = FetchDecision(cred, vp, vnode_id);

  switch (returnedAction) {
    case ACTION_RESPOND_ALLOW:
    case ACTION_RESPOND_ALLOW_COMPILER:
    case ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE: {
      auto proc = vfs_context_proc(ctx);
      if (proc) {
        pid_t pid = proc_pid(proc);
        pid_t ppid = proc_ppid(proc);
        // pid_t is 32-bit; pid is in upper 32 bits, ppid in lower.
        uint64_t val = ((uint64_t)pid << 32) | (ppid & 0xFFFFFFFF);
        vnode_pid_map_->set(vnode_id, val);
        if (returnedAction == ACTION_RESPOND_ALLOW_COMPILER && ppid != 0) {
          // Do some additional bookkeeping for compilers:
          // We associate the pid with a compiler so that when we see it later
          // in the context of a KAUTH_FILEOP event, we'll recognize it.
          compiler_pid_set_->set(pid, ppid);
          // And start polling for the compiler process termination, so that we
          // can remove the pid from our cache of compiler pids.
          MonitorCompilerPidForExit(pid);
        }
      }
      return KAUTH_RESULT_ALLOW;
    }
    case ACTION_RESPOND_DENY:
      *errno = EPERM;
      return KAUTH_RESULT_DENY;
    case ACTION_RESPOND_TOOLONG:
      *errno = ENAMETOOLONG;
      return KAUTH_RESULT_DENY;
    default:
      // NOTE: Any unknown response or error condition causes us to fail open.
      // Whilst from a security perspective this is bad, it's important that
      // we don't break user's machines.
      return KAUTH_RESULT_DEFER;
  }
}

void SantaDecisionManager::FileOpCallback(
    const kauth_action_t action, const vnode_t vp,
    const char *path, const char *new_path) {
  if (!ClientConnected() || proc_selfpid() == client_pid_) return;

  if (vp && action == KAUTH_FILEOP_EXEC) {
    auto context = vfs_context_create(nullptr);
    auto vnode_id = GetVnodeIDForVnode(context, vp);
    vfs_context_rele(context);

    auto message = NewMessage(nullptr);
    message->vnode_id = vnode_id;
    message->action = ACTION_NOTIFY_EXEC;
    strlcpy(message->path, path, sizeof(message->path));
    uint64_t val = vnode_pid_map_->get(vnode_id);
    if (val) {
      // pid_t is 32-bit, so pid is in upper 32 bits, ppid in lower.
      message->pid = (val >> 32);
      message->ppid = (val & ~0xFFFFFFFF00000000);
    }
    PostToLogQueue(message);
    delete message;
    return;
  }

  // For transitive whitelisting decisions, we must check for KAUTH_FILEOP_CLOSE events from a
  // known compiler process. But we must also check for KAUTH_FILEOP_RENAME events because clang
  // under Xcode 9 will, if the output file already exists, write to a temp file, delete the
  // existing file, then rename the temp file, without ever closing it.  So in this scenario,
  // the KAUTH_FILEOP_RENAME is the only chance we have of whitelisting the output.
  if (action == KAUTH_FILEOP_CLOSE || (action == KAUTH_FILEOP_RENAME && new_path)) {
    auto message = NewMessage(nullptr);
    if (IsCompilerProcess(message->pid)) {
      // Fill out the rest of the message details and send it to the decision queue.
      auto context = vfs_context_create(nullptr);
      vnode_t real_vp = vp;
      // We have to manually look up the vnode pointer from new_path for KAUTH_FILEOP_RENAME.
      if (!real_vp && new_path && ERR_SUCCESS == vnode_lookup(new_path, 0, &real_vp, context)) {
        vnode_put(real_vp);
      }
      if (real_vp) message->vnode_id = GetVnodeIDForVnode(context, real_vp);
      vfs_context_rele(context);
      message->action = ACTION_NOTIFY_WHITELIST;
      const char *real_path = (action == KAUTH_FILEOP_CLOSE) ? path : new_path;
      strlcpy(message->path, real_path, sizeof(message->path));
      proc_name(message->pid, message->pname, sizeof(message->pname));
      PostToDecisionQueue(message);
      // Add a temporary allow rule to the decision cache for this vnode_id
      // while SNTCompilerController decides whether or not to add a
      // permanent rule for the new file to the rules database.  This is
      // because checking if the file is a Mach-O binary and hashing it might
      // not finish before an attempt to execute it.
      AddToCache(message->vnode_id, ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE, 0);
    }
    delete message;
    // Don't need to do anything else for FILEOP_CLOSE, but FILEOP_RENAME should fall through.
    if (action == KAUTH_FILEOP_CLOSE) return;
  }

  // Filter out modifications to locations that are definitely
  // not useful or made by santad.
  if (!strprefix(path, "/.") && !strprefix(path, "/dev")) {
    auto message = NewMessage(nullptr);
    strlcpy(message->path, path, sizeof(message->path));
    if (new_path) strlcpy(message->newpath, new_path, sizeof(message->newpath));
    proc_name(message->pid, message->pname, sizeof(message->pname));

    switch (action) {
      case KAUTH_FILEOP_WRITE:
        // This is actually a KAUTH_VNODE_WRITE_DATA event.
        message->action = ACTION_NOTIFY_WRITE;
        break;
      case KAUTH_FILEOP_RENAME:
        message->action = ACTION_NOTIFY_RENAME;
        break;
      case KAUTH_FILEOP_LINK:
        message->action = ACTION_NOTIFY_LINK;
        break;
      case KAUTH_FILEOP_EXCHANGE:
        message->action = ACTION_NOTIFY_EXCHANGE;
        break;
      case KAUTH_FILEOP_DELETE:
        message->action = ACTION_NOTIFY_DELETE;
        break;
      default:
        delete message;
        return;
    }

    PostToLogQueue(message);
    delete message;
  }
}

#undef super

extern "C" int fileop_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
  auto sdm = OSDynamicCast(
      SantaDecisionManager, reinterpret_cast<OSObject *>(idata));

  if (unlikely(sdm == nullptr)) {
    LOGE("fileop_scope_callback called with no decision manager");
    return KAUTH_RESULT_DEFER;
  }

  vnode_t vp = nullptr;
  char *path = nullptr;
  char *new_path = nullptr;

  switch (action) {
    case KAUTH_FILEOP_CLOSE:
      // We only care about KAUTH_FILEOP_CLOSE events where the closed file
      // was modified.
      if (!(arg2 & KAUTH_FILEOP_CLOSE_MODIFIED))
        return KAUTH_RESULT_DEFER;
      // Intentional fallthrough to get vnode reference.
      [[fallthrough]];
    case KAUTH_FILEOP_DELETE:
    case KAUTH_FILEOP_EXEC:
      vp = reinterpret_cast<vnode_t>(arg0);
      if (vp && vnode_vtype(vp) != VREG) return KAUTH_RESULT_DEFER;
      path = reinterpret_cast<char *>(arg1);
      break;
    case KAUTH_FILEOP_RENAME:
    case KAUTH_FILEOP_EXCHANGE:
    case KAUTH_FILEOP_LINK:
      path = reinterpret_cast<char *>(arg0);
      new_path = reinterpret_cast<char *>(arg1);
      break;
    default:
      return KAUTH_RESULT_DEFER;
  }

  sdm->IncrementListenerInvocations();
  sdm->FileOpCallback(action, vp, path, new_path);
  sdm->DecrementListenerInvocations();

  return KAUTH_RESULT_DEFER;
}

extern "C" int vnode_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
  auto sdm = OSDynamicCast(
      SantaDecisionManager, reinterpret_cast<OSObject *>(idata));

  if (unlikely(sdm == nullptr)) {
    LOGE("vnode_scope_callback called with no decision manager");
    return KAUTH_RESULT_DEFER;
  }

  vnode_t vp = reinterpret_cast<vnode_t>(arg1);

  // We only care about regular files.
  if (vnode_vtype(vp) != VREG) return KAUTH_RESULT_DEFER;

  if ((action & KAUTH_VNODE_EXECUTE) && !(action & KAUTH_VNODE_ACCESS)) {
    sdm->IncrementListenerInvocations();
    int result = sdm->VnodeCallback(credential,
                                    reinterpret_cast<vfs_context_t>(arg0),
                                    vp,
                                    reinterpret_cast<int *>(arg3));
    sdm->DecrementListenerInvocations();
    return result;
  } else if (action & KAUTH_VNODE_WRITE_DATA || action & KAUTH_VNODE_APPEND_DATA) {
    sdm->IncrementListenerInvocations();
    if (!(action & KAUTH_VNODE_ACCESS)) {
      auto vnode_id = sdm->GetVnodeIDForVnode(reinterpret_cast<vfs_context_t>(arg0), vp);
      sdm->RemoveFromCache(vnode_id);
    }
    char path[MAXPATHLEN];
    int pathlen = MAXPATHLEN;
    vn_getpath(vp, path, &pathlen);
    // KAUTH_VNODE_WRITE_DATA events are translated into fake KAUTH_FILEOP_WRITE
    // events so that we can handle them in the FileOpCallback function.
    sdm->FileOpCallback(KAUTH_FILEOP_WRITE, vp, path, nullptr);
    sdm->DecrementListenerInvocations();
  }

  return KAUTH_RESULT_DEFER;
}
