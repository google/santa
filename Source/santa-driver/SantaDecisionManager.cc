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

SantaDecisionManager *SantaDecisionManager::WithQueueAndPID(
    IOSharedDataQueue *queue, pid_t pid) {
  SantaDecisionManager *me = new SantaDecisionManager;

  if (me && !me->InitWithQueueAndPID(queue, pid)) {
    me->free();
    return NULL;
  }

  return me;
}

bool SantaDecisionManager::InitWithQueueAndPID(
    IOSharedDataQueue *queue, pid_t pid) {
  if (!super::init()) return false;

  if (!pid) return false;
  if (!queue) return false;

  listener_invocations_ = 0;
  dataqueue_ = queue;
  owning_pid_ = pid;
  owning_proc_ = proc_find(pid);

  if (!(dataqueue_lock_ = IORWLockAlloc())) return FALSE;
  if (!(cached_decisions_lock_ = IORWLockAlloc())) return FALSE;
  if (!(cached_decisions_ = OSDictionary::withCapacity(1000))) return FALSE;

  return TRUE;
}

void SantaDecisionManager::free() {
  proc_rele(owning_proc_);

  if (cached_decisions_) {
    cached_decisions_->release();
    cached_decisions_ = NULL;
  }

  if (cached_decisions_lock_) {
    IORWLockFree(cached_decisions_lock_);
    cached_decisions_lock_ = NULL;
  }

  if (dataqueue_lock_) {
    IORWLockFree(dataqueue_lock_);
    dataqueue_lock_ = NULL;
  }

  super::free();
}

# pragma mark Cache Management

void SantaDecisionManager::AddToCache(
    const char *identifier, santa_action_t decision, uint64_t microsecs) {
  IORWLockWrite(cached_decisions_lock_);

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

  IORWLockUnlock(cached_decisions_lock_);
}

void SantaDecisionManager::CacheCheck(const char *identifier) {
  IORWLockRead(cached_decisions_lock_);
  bool shouldInvalidate = (cached_decisions_->getObject(identifier) != NULL);
  IORWLockUnlock(cached_decisions_lock_);
  if (shouldInvalidate) {
    IORWLockWrite(cached_decisions_lock_);
    cached_decisions_->removeObject(identifier);
    IORWLockUnlock(cached_decisions_lock_);
  }
}

uint64_t SantaDecisionManager::CacheCount() {
  return cached_decisions_->getCount();
}

void SantaDecisionManager::ClearCache() {
  IORWLockWrite(cached_decisions_lock_);
  cached_decisions_->flushCollection();
  IORWLockUnlock(cached_decisions_lock_);
}

santa_action_t SantaDecisionManager::GetFromCache(const char *identifier) {
  santa_action_t result = ACTION_UNSET;
  uint64_t decision_time = 0;

  IORWLockRead(cached_decisions_lock_);
  SantaMessage *cached_decision = OSDynamicCast(
      SantaMessage, cached_decisions_->getObject(identifier));
  if (cached_decision) {
    result = cached_decision->getAction();
    decision_time = cached_decision->getMicrosecs();
  }
  IORWLockUnlock(cached_decisions_lock_);

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
      IORWLockWrite(cached_decisions_lock_);
      cached_decisions_->removeObject(identifier);
      IORWLockUnlock(cached_decisions_lock_);
      return ACTION_UNSET;
    }
  }

  return result;
}

# pragma mark Queue Management

bool SantaDecisionManager::PostToQueue(santa_message_t message) {
  IORWLockWrite(dataqueue_lock_);
  bool kr = dataqueue_->enqueue(&message, sizeof(message));
  IORWLockUnlock(dataqueue_lock_);
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

SInt32 SantaDecisionManager::GetListenerInvocations() {
  return listener_invocations_;
}

void SantaDecisionManager::IncrementListenerInvocations() {
  OSIncrementAtomic(&listener_invocations_);
}

void SantaDecisionManager::DecrementListenerInvocations() {
  OSDecrementAtomic(&listener_invocations_);
}

bool SantaDecisionManager::MatchesOwningPID(const pid_t other_pid) {
  return (owning_pid_ == other_pid);
}

# pragma mark Listener Control

kern_return_t SantaDecisionManager::StartListener() {
  process_listener_ = kauth_listen_scope(KAUTH_SCOPE_PROCESS,
                                         process_scope_callback,
                                         reinterpret_cast<void *>(this));
  if (!process_listener_) return kIOReturnInternalError;
  LOGD("Process listener started.");

  vnode_listener_ = kauth_listen_scope(KAUTH_SCOPE_VNODE,
                                       vnode_scope_callback,
                                       reinterpret_cast<void *>(this));
  if (!vnode_listener_) return kIOReturnInternalError;

  LOGD("Vnode listener started.");

  return kIOReturnSuccess;
}

kern_return_t SantaDecisionManager::StopListener() {
  kauth_unlisten_scope(vnode_listener_);
  vnode_listener_ = NULL;

  kauth_unlisten_scope(process_listener_);
  process_listener_ = NULL;

  // Wait for any active invocations to finish before returning
  do {
    IOSleep(5);
  } while (GetListenerInvocations());

  // Delete any cached decisions
  ClearCache();

  LOGD("Vnode listener stopped.");
  LOGD("Process listener stopped.");

  return kIOReturnSuccess;
}

#undef super

#pragma mark Kauth Callbacks

extern "C" int process_scope_callback(
    kauth_cred_t credential, void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
  if (idata == NULL) {
    LOGE("Process callback established without valid decision manager.");
    return KAUTH_RESULT_ALLOW;
  }
  SantaDecisionManager *sdm = OSDynamicCast(
      SantaDecisionManager, reinterpret_cast<OSObject *>(idata));

  // NOTE: this prevents a debugger from attaching to an existing santad
  // process but doesn't prevent starting santad under a debugger. This check
  // is only here to try and prevent the user from deadlocking their machine
  // by attaching a debugger, so if they work around it and end up deadlocking,
  // that's their problem.
  if (action == KAUTH_PROCESS_CANTRACE &&
      sdm->MatchesOwningPID(proc_pid((proc_t)arg0))) {
    *(reinterpret_cast<int *>(arg1)) = EPERM;
    LOGD("Denied debugger access");
    return KAUTH_RESULT_DENY;
  }

  return KAUTH_RESULT_ALLOW;
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

  // Filter for only WRITE_DATA actions
  if (action & KAUTH_VNODE_WRITE_DATA ||
      action & KAUTH_VNODE_APPEND_DATA ||
      action & KAUTH_VNODE_DELETE) {
    char vnode_id_str[MAX_VNODE_ID_STR];
    snprintf(vnode_id_str, MAX_VNODE_ID_STR, "%llu",
             sdm->GetVnodeIDForVnode(vfs_context, vnode));

    // If an execution request is pending, deny write
    if (sdm->GetFromCache(vnode_id_str) == ACTION_REQUEST_CHECKBW) {
      LOGD("Denying write due to pending execution: %s", vnode_id_str);
      *(reinterpret_cast<int *>(arg3)) = EACCES;
      return KAUTH_RESULT_DENY;
    }

    // Otherwise remove from cache
    sdm->CacheCheck(vnode_id_str);

    return returnResult;
  }

  // Filter for only EXECUTE actions
  if (action & KAUTH_VNODE_EXECUTE) {
    sdm->IncrementListenerInvocations();

    // Fetch decision
    santa_action_t returnedAction = sdm->FetchDecision(
        credential, vfs_context, vnode);

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
        // we don't break user's machines. Every fallen open response will come
        // through this code path and cause this log entry to be created, so we
        // can investigate each case and try to fix the root cause.
        char path[MAX_PATH_LEN];
        int name_len = MAX_PATH_LEN;
        if (vn_getpath(vnode, path, &name_len) != 0) {
          path[0] = '\0';
        }
        LOGW("Didn't receive a valid response for %s. Received: %d.",
             path,
             returnedAction);
        break;
    }

    sdm->DecrementListenerInvocations();

    return returnResult;
  }

  return returnResult;
}
