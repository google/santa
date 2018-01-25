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

  root_decision_cache_ = new SantaCache<uint64_t>(5000, 2);
  non_root_decision_cache_ = new SantaCache<uint64_t>(500, 2);
  vnode_pid_map_ = new SantaCache<uint64_t>(2000, 5);

  decision_dataqueue_ = IOSharedDataQueue::withEntries(
      kMaxDecisionQueueEvents, sizeof(santa_message_t));
  if (!decision_dataqueue_) return kIOReturnNoMemory;

  log_dataqueue_ = IOSharedDataQueue::withEntries(
      kMaxLogQueueEvents, sizeof(santa_message_t));
  if (!log_dataqueue_) return kIOReturnNoMemory;

  client_pid_ = 0;
  root_fsid_ = 0;

  ts_ = { .tv_sec = kRequestLoopSleepMilliseconds / 1000,
          .tv_nsec = kRequestLoopSleepMilliseconds % 1000 * 1000000 };

  return true;
}

void SantaDecisionManager::free() {
  delete root_decision_cache_;
  delete non_root_decision_cache_;
  delete vnode_pid_map_;

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

  // Determine root fsid
  vfs_context_t ctx = vfs_context_create(NULL);
  if (ctx) {
    vnode_t root = vfs_rootvnode();
    if (root) {
      root_fsid_ = GetVnodeIDForVnode(ctx, root) >> 32;
      vnode_put(root);
    }
    vfs_context_rele(ctx);
  }

  // Any decisions made while the daemon wasn't
  // connected should be cleared
  ClearCache();

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

#pragma mark Cache Management

/**
  Return the correct cache for a given identifier.

  @param identifier The identifier
  @return SantaCache* The cache to use
*/
SantaCache<uint64_t>* SantaDecisionManager::CacheForIdentifier(
    const uint64_t identifier) {
  return (identifier >> 32 == root_fsid_) ?
    root_decision_cache_ : non_root_decision_cache_;
}

void SantaDecisionManager::AddToCache(
    uint64_t identifier, santa_action_t decision, uint64_t microsecs) {
  // Decision is stored in upper 8 bits, timestamp in remaining 56.
  uint64_t val = ((uint64_t)decision << 56) | (microsecs & 0xFFFFFFFFFFFFFF);

  auto decision_cache = CacheForIdentifier(identifier);

  switch (decision) {
    case ACTION_REQUEST_BINARY:
      decision_cache->set(identifier, val, 0);
      break;
    case ACTION_RESPOND_ACK:
      decision_cache->set(identifier, val, ((uint64_t)ACTION_REQUEST_BINARY << 56));
      break;
    case ACTION_RESPOND_ALLOW:
    case ACTION_RESPOND_DENY:
      // TODO(bur): Avoid calling set() twice, finding and locking buckets is fast, but not free.
      if (decision_cache->set(identifier, val, ((uint64_t)ACTION_REQUEST_BINARY << 56))) {
        decision_cache->set(identifier, val, ((uint64_t)ACTION_RESPOND_ACK << 56));
      }
      break;
    default:
      break;
  }

  wakeup((void *)identifier);
}

void SantaDecisionManager::RemoveFromCache(uint64_t identifier) {
  CacheForIdentifier(identifier)->remove(identifier);
  if (unlikely(!identifier)) return;
  wakeup((void *)identifier);
}

uint64_t SantaDecisionManager::RootCacheCount() const {
  return root_decision_cache_->count();
}

uint64_t SantaDecisionManager::NonRootCacheCount() const {
  return non_root_decision_cache_->count();
}

void SantaDecisionManager::ClearCache(bool non_root_only) {
  if (!non_root_only) root_decision_cache_->clear();
  non_root_decision_cache_->clear();
}

#pragma mark Decision Fetching

santa_action_t SantaDecisionManager::GetFromCache(uint64_t identifier) {
  auto result = ACTION_UNSET;
  uint64_t decision_time = 0;

  auto decision_cache = CacheForIdentifier(identifier);

  uint64_t cache_val = decision_cache->get(identifier);
  if (cache_val == 0) return result;

  // Decision is stored in upper 8 bits, timestamp in remaining 56.
  result = (santa_action_t)(cache_val >> 56);
  decision_time = (cache_val & ~(0xFF00000000000000));

  if (RESPONSE_VALID(result)) {
    if (result == ACTION_RESPOND_DENY) {
      auto expiry_time = decision_time + (kMaxDenyCacheTimeMilliseconds * 1000);
      if (expiry_time < GetCurrentUptime()) {
        decision_cache->remove(identifier);
        return ACTION_UNSET;
      }
    }
  }

  return result;
}

santa_action_t SantaDecisionManager::GetFromDaemon(
    santa_message_t *message, uint64_t identifier) {
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
      msleep((void *)message->vnode_id, NULL, 0, "", &ts_);
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
    const uint64_t vnode_id) {
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
      msleep((void *)vnode_id, NULL, 0, "", &ts_);
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
      client_pid_ = 0;
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
    // If enqueue failed, pop an item off the queue and try again.
    uint32_t dataSize = 0;
    log_dataqueue_->dequeue(0, &dataSize);
    kr = log_dataqueue_->enqueue(message, sizeof(santa_message_t));
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

#pragma mark Callbacks

int SantaDecisionManager::VnodeCallback(const kauth_cred_t cred,
                                        const vfs_context_t ctx,
                                        const vnode_t vp,
                                        int *errno) {
  // Get ID for the vnode
  auto vnode_id = GetVnodeIDForVnode(ctx, vp);
  if (!vnode_id) return KAUTH_RESULT_DEFER;

  // Fetch decision
  auto returnedAction = FetchDecision(cred, vp, vnode_id);

  // If file has dirty blocks, remove from cache and deny. This would usually
  // be the case if a file has been written to and flushed but not yet
  // closed.
  if (vnode_hasdirtyblks(vp)) {
    RemoveFromCache(vnode_id);
    returnedAction = ACTION_RESPOND_DENY;
  }

  switch (returnedAction) {
    case ACTION_RESPOND_ALLOW: {
      auto proc = vfs_context_proc(ctx);
      if (proc) {
        pid_t pid = proc_pid(proc);
        pid_t ppid = proc_ppid(proc);
        // pid_t is 32-bit; pid is in upper 32 bits, ppid in lower.
        uint64_t val = ((uint64_t)pid << 32) | (ppid & 0xFFFFFFFF);
        vnode_pid_map_->set(vnode_id, val);
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

  if (vp) {
    auto context = vfs_context_create(nullptr);
    auto vnode_id = GetVnodeIDForVnode(context, vp);
    vfs_context_rele(context);

    if (action == KAUTH_FILEOP_CLOSE) {
      RemoveFromCache(vnode_id);
    } else if (action == KAUTH_FILEOP_EXEC) {
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
  }

  // Filter out modifications to locations that are definitely
  // not useful or made by santad.
  if (!strprefix(path, "/.") && !strprefix(path, "/dev")) {
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

  if (unlikely(sdm == nullptr)) {
    LOGE("fileop_scope_callback called with no decision manager");
    return KAUTH_RESULT_DEFER;
  }

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
  } else if (action & KAUTH_VNODE_WRITE_DATA) {
    sdm->IncrementListenerInvocations();
    char path[MAXPATHLEN];
    int pathlen = MAXPATHLEN;
    vn_getpath(vp, path, &pathlen);
    sdm->FileOpCallback(KAUTH_FILEOP_CLOSE, vp, path, nullptr);
    sdm->DecrementListenerInvocations();
  }

  return KAUTH_RESULT_DEFER;
}
