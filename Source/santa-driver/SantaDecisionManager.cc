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

#define super OSObject
OSDefineMetaClassAndStructors(SantaDecisionManager, OSObject);

#pragma mark Object Lifecycle

bool SantaDecisionManager::init() {
  if (!super::init()) return false;

  sdm_lock_grp_attr_ = lck_grp_attr_alloc_init();
  sdm_lock_grp_ = lck_grp_alloc_init("santa-locks", sdm_lock_grp_attr_);

  sdm_lock_attr_ = lck_attr_alloc_init();

  decision_dataqueue_lock_ = lck_mtx_alloc_init(sdm_lock_grp_, sdm_lock_attr_);
  log_dataqueue_lock_ = lck_mtx_alloc_init(sdm_lock_grp_, sdm_lock_attr_);
  cached_decisions_lock_ = lck_rw_alloc_init(sdm_lock_grp_, sdm_lock_attr_);
  vnode_pid_map_lock_ = lck_rw_alloc_init(sdm_lock_grp_, sdm_lock_attr_);

  cached_decisions_ = OSDictionary::withCapacity(1000);
  vnode_pid_map_ = OSDictionary::withCapacity(1000);

  decision_dataqueue_ = IOSharedDataQueue::withEntries(kMaxDecisionQueueEvents,
                                                       sizeof(santa_message_t));
  if (!decision_dataqueue_) return kIOReturnNoMemory;

  log_dataqueue_ = IOSharedDataQueue::withEntries(kMaxLogQueueEvents,
                                                  sizeof(santa_message_t));
  if (!log_dataqueue_) return kIOReturnNoMemory;

  client_pid_ = 0;

  return true;
}

void SantaDecisionManager::free() {
  if (cached_decisions_lock_) {
    lck_rw_free(cached_decisions_lock_, sdm_lock_grp_);
    cached_decisions_lock_ = nullptr;
  }

  if (vnode_pid_map_lock_) {
    lck_rw_free(vnode_pid_map_lock_, sdm_lock_grp_);
    vnode_pid_map_lock_ = nullptr;
  }

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
  OSSafeReleaseNULL(cached_decisions_);
  OSSafeReleaseNULL(vnode_pid_map_);

  super::free();
}

#pragma mark Client Management

void SantaDecisionManager::ConnectClient(pid_t pid) {
  if (!pid) return;

  // Any decisions made while the daemon wasn't
  // connected should be cleared
  ClearCache();

  client_pid_ = pid;

  failed_decision_queue_requests_ = 0;
  failed_log_queue_requests_ = 0;
}

void SantaDecisionManager::DisconnectClient(bool itDied) {
  if (client_pid_ < 1) return;
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
  vnode_listener_ = kauth_listen_scope(KAUTH_SCOPE_VNODE,
                                       vnode_scope_callback,
                                       reinterpret_cast<void *>(this));
  if (!vnode_listener_) return kIOReturnInternalError;

  fileop_listener_ = kauth_listen_scope(KAUTH_SCOPE_FILEOP,
                                        fileop_scope_callback,
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

#pragma mark Cache Management

void SantaDecisionManager::AddToCache(
    const char *identifier, santa_action_t decision, uint64_t microsecs) {
  if (cached_decisions_->getCount() > kMaxCacheSize) {
    // This could be made a _lot_ smarter, say only removing entries older
    // than a certain time period. However, with a kMaxCacheSize set
    // sufficiently large and a kMaxAllowCacheTimeMilliseconds set
    // sufficiently low, this should only ever occur if someone is purposefully
    // trying to make the cache grow.
    LOGI("Cache too large, flushing.");
    ClearCache();
  }

  if (decision == ACTION_REQUEST_BINARY) {
    auto pending = new SantaCachedDecision();
    pending->setAction(ACTION_REQUEST_BINARY, 0);
    lck_rw_lock_exclusive(cached_decisions_lock_);
    cached_decisions_->setObject(identifier, pending);
    lck_rw_unlock_exclusive(cached_decisions_lock_);
    pending->release();  // it was retained when added to the dictionary
  } else {
    lck_rw_lock_exclusive(cached_decisions_lock_);
    auto pending = OSDynamicCast(
        SantaCachedDecision, cached_decisions_->getObject(identifier));
    if (pending) {
      pending->setAction(decision, microsecs);
    }
    lck_rw_unlock_exclusive(cached_decisions_lock_);
  }
}

void SantaDecisionManager::CacheCheck(const char *identifier) {
  lck_rw_lock_shared(cached_decisions_lock_);
  auto shouldInvalidate = (cached_decisions_->getObject(identifier) != nullptr);
  if (shouldInvalidate) {
    if (!lck_rw_lock_shared_to_exclusive(cached_decisions_lock_)) {
      // shared_to_exclusive will return false if a previous reader upgraded
      // and if that happens the lock will have been unlocked. If that happens,
      // which is rare, relock exclusively.
      lck_rw_lock_exclusive(cached_decisions_lock_);
    }
    cached_decisions_->removeObject(identifier);
    lck_rw_unlock_exclusive(cached_decisions_lock_);
  } else {
    lck_rw_unlock_shared(cached_decisions_lock_);
  }
}

uint64_t SantaDecisionManager::CacheCount() const {
  return cached_decisions_->getCount();
}

void SantaDecisionManager::ClearCache() {
  lck_rw_lock_exclusive(cached_decisions_lock_);
  cached_decisions_->flushCollection();
  lck_rw_unlock_exclusive(cached_decisions_lock_);
}

#pragma mark Decision Fetching

santa_action_t SantaDecisionManager::GetFromCache(const char *identifier) {
  auto result = ACTION_UNSET;
  uint64_t decision_time = 0;

  lck_rw_lock_shared(cached_decisions_lock_);
  SantaCachedDecision *cached_decision = OSDynamicCast(
      SantaCachedDecision, cached_decisions_->getObject(identifier));
  if (cached_decision) {
    result = cached_decision->getAction();
    decision_time = cached_decision->getMicrosecs();
  }
  lck_rw_unlock_shared(cached_decisions_lock_);

  if (RESPONSE_VALID(result)) {
    auto diff_time = GetCurrentUptime();

    if (result == ACTION_RESPOND_ALLOW) {
      if ((kMaxAllowCacheTimeMilliseconds * 1000) > diff_time) {
        diff_time = 0;
      } else {
        diff_time -= (kMaxAllowCacheTimeMilliseconds * 1000);
      }
    } else if (result == ACTION_RESPOND_DENY) {
      if ((kMaxDenyCacheTimeMilliseconds * 1000) > diff_time) {
        diff_time = 0;
      } else {
        diff_time -= (kMaxDenyCacheTimeMilliseconds * 1000);
      }
    }

    if (decision_time < diff_time) {
      lck_rw_lock_exclusive(cached_decisions_lock_);
      cached_decisions_->removeObject(identifier);
      lck_rw_unlock_exclusive(cached_decisions_lock_);
      return ACTION_UNSET;
    }
  }

  return result;
}

santa_action_t SantaDecisionManager::GetFromDaemon(
    santa_message_t *message, const char *vnode_id_str) {
  auto return_action = ACTION_UNSET;

  // Wait for the daemon to respond or die.
  do {
    // Add pending request to cache.
    AddToCache(vnode_id_str, ACTION_REQUEST_BINARY, 0);

    // Send request to daemon...
    if (!PostToDecisionQueue(message)) {
      OSIncrementAtomic(&failed_decision_queue_requests_);
      if (failed_decision_queue_requests_ > kMaxDecisionQueueFailures) {
        LOGE("Failed to queue more than %d requests, killing daemon",
             kMaxDecisionQueueFailures);
        proc_signal(client_pid_, SIGKILL);
        client_pid_ = 0;
      }
      LOGE("Failed to queue request for %s.", message->path);
      CacheCheck(vnode_id_str);
      return ACTION_ERROR;
    }

    do {
      IOSleep(kRequestLoopSleepMilliseconds);
      return_action = GetFromCache(vnode_id_str);
    } while (return_action == ACTION_REQUEST_BINARY && ClientConnected());
  } while (!RESPONSE_VALID(return_action) && ClientConnected());

  // If response is still not valid, the daemon exited
  if (!RESPONSE_VALID(return_action)) {
    LOGE("Daemon process did not respond correctly. Allowing executions "
         "until it comes back. Executable path: %s", message->path);
    CacheCheck(vnode_id_str);
    return ACTION_ERROR;
  }

  return return_action;
}

santa_action_t SantaDecisionManager::FetchDecision(
    const kauth_cred_t cred,
    const vnode_t vp,
    const uint64_t vnode_id,
    const char *vnode_id_str) {
  if (!ClientConnected()) return ACTION_RESPOND_ALLOW;

  // Check to see if item is in cache
  auto return_action = GetFromCache(vnode_id_str);

  // If item was in cache return it.
  if (RESPONSE_VALID(return_action)) return return_action;

  // Get path
  char path[MAXPATHLEN];
  int name_len = MAXPATHLEN;
  if (vn_getpath(vp, path, &name_len) != 0) {
    path[0] = '\0';
  }

  auto message = NewMessage(cred);
  strlcpy(message->path, path, sizeof(message->path));
  message->action = ACTION_REQUEST_BINARY;
  message->vnode_id = vnode_id;
  proc_name(message->ppid, message->pname, sizeof(message->pname));
  return_action = GetFromDaemon(message, vnode_id_str);
  delete message;
  return return_action;
}

#pragma mark Misc

bool SantaDecisionManager::PostToDecisionQueue(santa_message_t *message) {
  lck_mtx_lock(decision_dataqueue_lock_);
  auto kr = decision_dataqueue_->enqueue(message, sizeof(santa_message_t));
  lck_mtx_unlock(decision_dataqueue_lock_);
  return kr;
}

bool SantaDecisionManager::PostToLogQueue(santa_message_t *message) {
  lck_mtx_lock(log_dataqueue_lock_);
  auto kr = log_dataqueue_->enqueue(message, sizeof(santa_message_t));
  if (!kr) {
    if (OSCompareAndSwap(0, 1, &failed_log_queue_requests_)) {
      LOGW("Dropping log queue messages");
    }
    // If enqueue failed, pop an item off the queue and try again.
    uint32_t dataSize = 0;
    log_dataqueue_->dequeue(0, &dataSize);
    kr = log_dataqueue_->enqueue(message, sizeof(santa_message_t));
  } else {
    OSCompareAndSwap(1, 0, &failed_log_queue_requests_);
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

#pragma mark Callbacks

int SantaDecisionManager::VnodeCallback(const kauth_cred_t cred,
                                        const vfs_context_t ctx,
                                        const vnode_t vp,
                                        int *errno) {
  // Only operate on regular files (not directories, symlinks, etc.).
  if (vnode_vtype(vp) != VREG) return KAUTH_RESULT_DEFER;

  // Get ID for the vnode and convert it to a string.
  auto vnode_id = GetVnodeIDForVnode(ctx, vp);
  char vnode_str[MAX_VNODE_ID_STR];
  snprintf(vnode_str, MAX_VNODE_ID_STR, "%llu", vnode_id);

  // Fetch decision
  auto returnedAction = FetchDecision(cred, vp, vnode_id, vnode_str);

  // If file has dirty blocks, remove from cache and deny. This would usually
  // be the case if a file has been written to and flushed but not yet
  // closed.
  if (vnode_hasdirtyblks(vp)) {
    CacheCheck(vnode_str);
    returnedAction = ACTION_RESPOND_DENY;
  }

  switch (returnedAction) {
    case ACTION_RESPOND_ALLOW: {
      auto proc = vfs_context_proc(ctx);
      if (proc) {
        auto pidWrapper = new SantaPIDAndPPID;
        pidWrapper->pid = proc_pid(proc);
        pidWrapper->ppid = proc_ppid(proc);
        lck_rw_lock_exclusive(vnode_pid_map_lock_);
        if (vnode_pid_map_->getCount() > 5000) {
          vnode_pid_map_->flushCollection();
        }
        vnode_pid_map_->setObject(vnode_str, pidWrapper);
        lck_rw_unlock_exclusive(vnode_pid_map_lock_);
        pidWrapper->release();
      }
      return KAUTH_RESULT_ALLOW;
    }
    case ACTION_RESPOND_DENY:
      *errno = EPERM;
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
  if (vp) {
    auto context = vfs_context_create(nullptr);
    auto vnode_id = GetVnodeIDForVnode(context, vp);
    vfs_context_rele(context);

    if (action == KAUTH_FILEOP_CLOSE) {
      char vnode_id_str[MAX_VNODE_ID_STR];
      snprintf(vnode_id_str, MAX_VNODE_ID_STR, "%llu", vnode_id);
      CacheCheck(vnode_id_str);
    } else if (action == KAUTH_FILEOP_EXEC) {
      auto message = NewMessage(nullptr);
      message->vnode_id = vnode_id;
      message->action = ACTION_NOTIFY_EXEC;
      strlcpy(message->path, path, sizeof(message->path));

      char vnode_str[MAX_VNODE_ID_STR];
      snprintf(vnode_str, MAX_VNODE_ID_STR, "%llu", vnode_id);

      lck_rw_lock_shared(vnode_pid_map_lock_);
      auto pidWrapper = OSDynamicCast(
          SantaPIDAndPPID, vnode_pid_map_->getObject(vnode_str));
      if (pidWrapper) {
        message->pid = pidWrapper->pid;
        message->ppid = pidWrapper->ppid;
      }
      lck_rw_unlock_shared(vnode_pid_map_lock_);

      PostToLogQueue(message);
      delete message;
      return;
    }
  }

  // Filter out modifications to locations that are definitely
  // not useful or made by santad.
  if (proc_selfpid() != client_pid_ &&
      !strprefix(path, "/.") &&
      !strprefix(path, "/dev")) {
    auto message = NewMessage(nullptr);
    strlcpy(message->path, path, sizeof(message->path));
    if (new_path) strlcpy(message->newpath, new_path, sizeof(message->newpath));
    proc_name(message->pid, message->pname, sizeof(message->pname));

    switch (action) {
      case KAUTH_FILEOP_CLOSE:
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

  vnode_t vp = nullptr;
  char *path = nullptr;
  char *new_path = nullptr;

  switch (action) {
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
  if (action & KAUTH_VNODE_ACCESS || idata == nullptr) {
    return KAUTH_RESULT_DEFER;
  }

  auto sdm = OSDynamicCast(
      SantaDecisionManager, reinterpret_cast<OSObject *>(idata));

  if (action & KAUTH_VNODE_EXECUTE) {
    sdm->IncrementListenerInvocations();
    int result = sdm->VnodeCallback(credential,
                                    reinterpret_cast<vfs_context_t>(arg0),
                                    reinterpret_cast<vnode_t>(arg1),
                                    reinterpret_cast<int *>(arg3));
    sdm->DecrementListenerInvocations();
    return result;
  } else if (action & KAUTH_VNODE_WRITE_DATA) {
    vnode_t vp = reinterpret_cast<vnode_t>(arg1);
    if (vnode_vtype(vp) != VREG) return KAUTH_RESULT_DEFER;
    sdm->IncrementListenerInvocations();
    char path[MAXPATHLEN];
    int pathlen = MAXPATHLEN;
    vn_getpath(vp, path, &pathlen);
    sdm->FileOpCallback(KAUTH_FILEOP_CLOSE, vp, path, nullptr);
    sdm->DecrementListenerInvocations();
  }

  return KAUTH_RESULT_DEFER;
}
