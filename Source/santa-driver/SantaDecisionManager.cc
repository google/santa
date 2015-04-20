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
  sdm_lock_grp_ = lck_grp_alloc_init("santa-locks", lck_grp_attr_alloc_init());
  dataqueue_lock_ = lck_mtx_alloc_init(sdm_lock_grp_, lck_attr_alloc_init());
  cached_decisions_lock_ = lck_rw_alloc_init(sdm_lock_grp_,
                                             lck_attr_alloc_init());

  cached_decisions_ = OSDictionary::withCapacity(1000);

  owning_pid_ = 0;

  return kIOReturnSuccess;
}

void SantaDecisionManager::free() {
  if (cached_decisions_) {
    cached_decisions_->release();
    cached_decisions_ = NULL;
  }

  if (cached_decisions_lock_) {
    lck_rw_free(cached_decisions_lock_, sdm_lock_grp_);
    cached_decisions_lock_ = NULL;
  }

  if (dataqueue_lock_ ) {
    lck_mtx_free(dataqueue_lock_, sdm_lock_grp_);
    dataqueue_lock_ = NULL;
  }

  if (sdm_lock_grp_) {
    lck_grp_free(sdm_lock_grp_);
    sdm_lock_grp_ = NULL;
  }

  super::free();
}

#pragma mark Client Management

void SantaDecisionManager::ConnectClient(IOSharedDataQueue *queue, pid_t pid) {
  if (!pid) return;
  if (!queue) return;

  // Any decisions made while the daemon wasn't
  // connected should be cleared
  ClearCache();

  lck_mtx_lock(dataqueue_lock_);
  dataqueue_ = queue;
  dataqueue_->retain();
  lck_mtx_unlock(dataqueue_lock_);

  owning_pid_ = pid;
  owning_proc_ = proc_find(pid);
  failed_queue_requests_ = 0;
}

void SantaDecisionManager::DisconnectClient() {
  if (owning_pid_ < 1) return;

  owning_pid_ = -1;

  // Ask santad to shutdown, in case it's running.
  santa_message_t message;
  message.action = ACTION_REQUEST_SHUTDOWN;
  message.userId = 0;
  message.pid = 0;
  message.ppid = 0;
  message.vnode_id = 0;
  PostToQueue(message);

  lck_mtx_lock(dataqueue_lock_);
  dataqueue_->release();
  dataqueue_ = NULL;
  lck_mtx_unlock(dataqueue_lock_);

  proc_rele(owning_proc_);
  owning_proc_ = NULL;
}

bool SantaDecisionManager::ClientConnected() {
  return owning_pid_ > 0;
}

# pragma mark Listener Control

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
  vnode_listener_ = NULL;

  kauth_unlisten_scope(fileop_listener_);
  fileop_listener_ = NULL;

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
  lck_rw_lock_exclusive(cached_decisions_lock_);

  if (cached_decisions_->getCount() > kMaxCacheSize) {
    // This could be made a _lot_ smarter, say only removing entries older
    // than a certain time period. However, with a kMaxCacheSize set
    // sufficiently large and a kMaxAllowCacheTimeMilliseconds set
    // sufficiently low, this should only ever occur if someone is purposefully
    // trying to make the cache grow.
    LOGD("Cache too large, flushing.");
    cached_decisions_->flushCollection();
  }

  if (decision == ACTION_REQUEST_CHECKBW) {
    SantaMessage *pending = new SantaMessage();
    pending->setAction(ACTION_REQUEST_CHECKBW, 0);
    cached_decisions_->setObject(identifier, pending);
    pending->release();  // it was retained when added to the dictionary
  } else {
    SantaMessage *pending = OSDynamicCast(
        SantaMessage, cached_decisions_->getObject(identifier));
    if (pending) {
      pending->setAction(decision, microsecs);
    }
  }

  lck_rw_unlock_exclusive(cached_decisions_lock_);
}

void SantaDecisionManager::CacheCheck(const char *identifier) {
  lck_rw_lock_shared(cached_decisions_lock_);
  bool shouldInvalidate = (cached_decisions_->getObject(identifier) != NULL);
  if (shouldInvalidate) {
    lck_rw_lock_shared_to_exclusive(cached_decisions_lock_);
    cached_decisions_->removeObject(identifier);
    lck_rw_unlock_exclusive(cached_decisions_lock_);
  } else {
    lck_rw_unlock_shared(cached_decisions_lock_);
  }
}

uint64_t SantaDecisionManager::CacheCount() {
  return cached_decisions_->getCount();
}

void SantaDecisionManager::ClearCache() {
  lck_rw_lock_exclusive(cached_decisions_lock_);
  cached_decisions_->flushCollection();
  lck_rw_unlock_exclusive(cached_decisions_lock_);
}

santa_action_t SantaDecisionManager::GetFromCache(const char *identifier) {
  santa_action_t result = ACTION_UNSET;
  uint64_t decision_time = 0;

  lck_rw_lock_shared(cached_decisions_lock_);
  SantaMessage *cached_decision = OSDynamicCast(
      SantaMessage, cached_decisions_->getObject(identifier));
  if (cached_decision) {
    result = cached_decision->getAction();
    decision_time = cached_decision->getMicrosecs();
  }
  lck_rw_unlock_shared(cached_decisions_lock_);

  if (CHECKBW_RESPONSE_VALID(result)) {
    uint64_t diff_time = GetCurrentUptime();

    if (result == ACTION_RESPOND_CHECKBW_ALLOW) {
      if ((kMaxAllowCacheTimeMilliseconds * 1000) > diff_time) {
        diff_time = 0;
      } else {
        diff_time -= (kMaxAllowCacheTimeMilliseconds * 1000);
      }
    } else if (result == ACTION_RESPOND_CHECKBW_DENY) {
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

# pragma mark Queue Management

bool SantaDecisionManager::PostToQueue(santa_message_t message) {
  lck_mtx_lock(dataqueue_lock_);
  bool kr = false;
  if (dataqueue_) {
    kr = dataqueue_->enqueue(&message, sizeof(message));
  }
  lck_mtx_unlock(dataqueue_lock_);
  return kr;
}

santa_action_t SantaDecisionManager::FetchDecision(
    const kauth_cred_t credential,
    const vfs_context_t vfs_context,
    const vnode_t vnode) {
  santa_action_t return_action = ACTION_UNSET;

  // Fetch Vnode ID & string
  uint64_t vnode_id = GetVnodeIDForVnode(vfs_context, vnode);
  char vnode_id_str[MAX_VNODE_ID_STR];
  snprintf(vnode_id_str, MAX_VNODE_ID_STR, "%llu", vnode_id);

  // Check to see if item is in cache
  return_action = GetFromCache(vnode_id_str);

  // If item wasn't in cache, fetch decision from daemon.
  if (!CHECKBW_RESPONSE_VALID(return_action)) {
    // Add pending request to cache
    AddToCache(vnode_id_str, ACTION_REQUEST_CHECKBW, 0);

    // Get path
    char path[MAX_PATH_LEN];
    int name_len = MAX_PATH_LEN;
    if (vn_getpath(vnode, path, &name_len) != 0) {
      path[0] = '\0';
    }

    if (!ClientConnected()) {
      LOGI("Execution request without daemon running: %s", path);
      AddToCache(vnode_id_str,
                 ACTION_RESPOND_CHECKBW_ALLOW,
                 GetCurrentUptime());
      return ACTION_RESPOND_CHECKBW_ALLOW;
    }

    // Prepare to send message to daemon
    santa_message_t message;
    strncpy(message.path, path, MAX_PATH_LEN);
    message.userId = kauth_cred_getuid(credential);
    message.pid = proc_selfpid();
    message.ppid = proc_selfppid();
    message.action = ACTION_REQUEST_CHECKBW;
    message.vnode_id = vnode_id;

    // Wait for the daemon to respond or die.
    do {
      // Send request to daemon...
      if (!PostToQueue(message)) {
        OSIncrementAtomic(&failed_queue_requests_);
        if (failed_queue_requests_ > kMaxQueueFailures) {
          LOGE("Failed to queue more than %d requests, killing daemon",
               kMaxQueueFailures);
          proc_signal(owning_pid_, SIGKILL);
        }
        LOGE("Failed to queue request for %s.", path);
        CacheCheck(vnode_id_str);
        return ACTION_ERROR;
      }

      // ... and wait for it to respond. If after kRequestLoopSleepMilliseconds
      // * kMaxRequestLoops it still hasn't responded, send request again.
      for (int i = 0; i < kMaxRequestLoops; ++i) {
        IOSleep(kRequestLoopSleepMilliseconds);
        return_action = GetFromCache(vnode_id_str);
        if (CHECKBW_RESPONSE_VALID(return_action)) break;
      }
    } while (!CHECKBW_RESPONSE_VALID(return_action) &&
             proc_exiting(owning_proc_) == 0);

    // If response is still not valid, the daemon exited
    if (!CHECKBW_RESPONSE_VALID(return_action)) {
      LOGE("Daemon process did not respond correctly. Allowing executions "
           "until it comes back.");
      CacheCheck(vnode_id_str);
      return ACTION_ERROR;
    }
  }

  return return_action;
}

# pragma mark Misc

uint64_t SantaDecisionManager::GetVnodeIDForVnode(const vfs_context_t context,
                                                  const vnode_t vp) {
  struct vnode_attr vap;
  VATTR_INIT(&vap);
  VATTR_WANTED(&vap, va_fileid);
  vnode_getattr(vp, &vap, context);
  return vap.va_fileid;
}

uint64_t SantaDecisionManager::GetCurrentUptime() {
  clock_sec_t sec;
  clock_usec_t usec;
  clock_get_system_microtime(&sec, &usec);
  return (uint64_t)((sec * 1000000) + usec);
}

# pragma mark Invocation Tracking & PID comparison

void SantaDecisionManager::IncrementListenerInvocations() {
  OSIncrementAtomic(&listener_invocations_);
}

void SantaDecisionManager::DecrementListenerInvocations() {
  OSDecrementAtomic(&listener_invocations_);
}

#undef super

#pragma mark Kauth Callbacks

extern "C" int fileop_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
  if (!(action == KAUTH_FILEOP_CLOSE && arg2 & KAUTH_FILEOP_CLOSE_MODIFIED)) {
    return KAUTH_RESULT_DEFER;
  }

  if (idata == NULL) {
    LOGE("FileOp callback established without valid decision manager.");
    return KAUTH_RESULT_DEFER;
  }

  SantaDecisionManager *sdm = OSDynamicCast(
      SantaDecisionManager, reinterpret_cast<OSObject *>(idata));
  char vnode_id_str[MAX_VNODE_ID_STR];
  snprintf(vnode_id_str, MAX_VNODE_ID_STR, "%llu",
           sdm->GetVnodeIDForVnode(NULL, (vnode_t)arg0));
  sdm->CacheCheck(vnode_id_str);

  return KAUTH_RESULT_DEFER;
}

extern "C" int vnode_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
  // The default action is to defer
  int returnResult = KAUTH_RESULT_DEFER;

  // Cast arguments to correct types
  if (idata == NULL) {
    LOGE("Vnode callback established without valid decision manager.");
    return returnResult;
  }
  SantaDecisionManager *sdm = OSDynamicCast(
      SantaDecisionManager, reinterpret_cast<OSObject *>(idata));
  vfs_context_t vfs_context = reinterpret_cast<vfs_context_t>(arg0);
  vnode_t vnode = reinterpret_cast<vnode_t>(arg1);

  // Only operate on regular files (not directories, symlinks, etc.)
  vtype vt = vnode_vtype(vnode);
  if (vt != VREG) return returnResult;

  // Don't operate on ACCESS events, as they're advisory
  if (action & KAUTH_VNODE_ACCESS) return returnResult;

  // Filter for only EXECUTE actions
  if (action & KAUTH_VNODE_EXECUTE) {
    sdm->IncrementListenerInvocations();

    // Fetch decision
    santa_action_t returnedAction = sdm->FetchDecision(
        credential, vfs_context, vnode);

    // If file has dirty blocks, remove from cache and deny. This would usually
    // be the case if a file has been written to and flushed but not yet
    // closed.
    if (vnode_hasdirtyblks(vnode)) {
      char vnode_id_str[MAX_VNODE_ID_STR];
      snprintf(vnode_id_str, MAX_VNODE_ID_STR, "%llu",
               sdm->GetVnodeIDForVnode(vfs_context, vnode));
      sdm->CacheCheck(vnode_id_str);
      returnedAction = ACTION_RESPOND_CHECKBW_DENY;
    }

    switch (returnedAction) {
      case ACTION_RESPOND_CHECKBW_ALLOW:
        returnResult = KAUTH_RESULT_ALLOW;
        break;
      case ACTION_RESPOND_CHECKBW_DENY:
        *(reinterpret_cast<int *>(arg3)) = EACCES;
        returnResult = KAUTH_RESULT_DENY;
        break;
      default:
        // NOTE: Any unknown response or error condition causes us to fail open.
        // Whilst from a security perspective this is bad, it's important that
        // we don't break user's machines.
        break;
    }

    sdm->DecrementListenerInvocations();

    return returnResult;
  }

  return returnResult;
}
