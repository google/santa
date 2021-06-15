/// Copyright 2021 Google Inc. All rights reserved.
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

#import "Source/santad/EventProviders/SNTCachingEndpointSecurityManager.h"

#import "Source/common/SNTLogging.h"
#import "Source/common/SantaCache.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

uint64_t GetCurrentUptime() {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC);
}
template <>
uint64_t SantaCacheHasher<santa_vnode_id_t>(santa_vnode_id_t const &t) {
  return (SantaCacheHasher<uint64_t>(t.fsid) << 1) ^ SantaCacheHasher<uint64_t>(t.fileid);
}

@implementation SNTCachingEndpointSecurityManager {
  SantaCache<santa_vnode_id_t, uint64_t> *_decisionCache;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    // TODO(rah): Consider splitting into root/non-root cache
    _decisionCache = new SantaCache<santa_vnode_id_t, uint64_t>();
  }

  return self;
}

- (void)dealloc {
  if (_decisionCache) delete _decisionCache;
}

- (BOOL)respondFromCache:(es_message_t *)m API_AVAILABLE(macos(10.15)) {
  auto vnode_id = [self vnodeIDForFile:m->event.exec.target->executable];
  while (true) {
    // Check to see if item is in cache
    auto return_action = [self checkCache:vnode_id];

    // If item was in cache with a valid response, return it.
    // If item is in cache but hasn't received a response yet, sleep for a bit.
    // If item is not in cache, break out of loop and forward request to callback.
    if (RESPONSE_VALID(return_action)) {
      switch (return_action) {
        case ACTION_RESPOND_ALLOW:
          es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, true);
          break;
        case ACTION_RESPOND_ALLOW_COMPILER: {
          pid_t pid = audit_token_to_pid(m->process->audit_token);
          [self setIsCompilerPID:pid];
          // Don't let ES cache compilers
          es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, false);
          break;
        }
        default: es_respond_auth_result(self.client, m, ES_AUTH_RESULT_DENY, false); break;
      }
      return YES;
    } else if (return_action == ACTION_REQUEST_BINARY || return_action == ACTION_RESPOND_ACK) {
      // TODO(rah): Look at a replacement for msleep(), maybe NSCondition
      usleep(5000);
    } else {
      break;
    }
  }

  [self addToCache:vnode_id decision:ACTION_REQUEST_BINARY currentTicks:0];
  return NO;
}

- (int)postAction:(santa_action_t)action
       forMessage:(santa_message_t)sm API_AVAILABLE(macos(10.15)) {
  es_respond_result_t ret;
  switch (action) {
    case ACTION_RESPOND_ALLOW_COMPILER:
      [self setIsCompilerPID:sm.pid];

      // Allow the exec and cache in our internal cache but don't let ES cache, because then
      // we won't see future execs of the compiler in order to record the PID.
      [self addToCache:sm.vnode_id
              decision:ACTION_RESPOND_ALLOW_COMPILER
          currentTicks:GetCurrentUptime()];
      ret = es_respond_auth_result(self.client, (es_message_t *)sm.es_message, ES_AUTH_RESULT_ALLOW,
                                   false);
      break;
    case ACTION_RESPOND_ALLOW:
    case ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE:
      [self addToCache:sm.vnode_id decision:ACTION_RESPOND_ALLOW currentTicks:GetCurrentUptime()];
      ret = es_respond_auth_result(self.client, (es_message_t *)sm.es_message, ES_AUTH_RESULT_ALLOW,
                                   true);
      break;
    case ACTION_RESPOND_DENY:
      [self addToCache:sm.vnode_id decision:ACTION_RESPOND_DENY currentTicks:GetCurrentUptime()];
      OS_FALLTHROUGH;
    case ACTION_RESPOND_TOOLONG:
      ret = es_respond_auth_result(self.client, (es_message_t *)sm.es_message, ES_AUTH_RESULT_DENY,
                                   false);
      break;
    case ACTION_RESPOND_ACK: return ES_RESPOND_RESULT_SUCCESS;
    default: ret = ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
  }

  return ret;
}

- (void)addToCache:(santa_vnode_id_t)identifier
          decision:(santa_action_t)decision
      currentTicks:(uint64_t)microsecs {
  switch (decision) {
    case ACTION_REQUEST_BINARY:
      _decisionCache->set(identifier, (uint64_t)ACTION_REQUEST_BINARY << 56, 0);
      break;
    case ACTION_RESPOND_ACK:
      _decisionCache->set(identifier, (uint64_t)ACTION_RESPOND_ACK << 56,
                          ((uint64_t)ACTION_REQUEST_BINARY << 56));
      break;
    case ACTION_RESPOND_ALLOW:
    case ACTION_RESPOND_ALLOW_COMPILER:
    case ACTION_RESPOND_DENY: {
      // Decision is stored in upper 8 bits, timestamp in remaining 56.
      uint64_t val = ((uint64_t)decision << 56) | (microsecs & 0xFFFFFFFFFFFFFF);
      if (!_decisionCache->set(identifier, val, ((uint64_t)ACTION_REQUEST_BINARY << 56))) {
        _decisionCache->set(identifier, val, ((uint64_t)ACTION_RESPOND_ACK << 56));
      }
      break;
    }
    case ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE: {
      // Decision is stored in upper 8 bits, timestamp in remaining 56.
      uint64_t val = ((uint64_t)decision << 56) | (microsecs & 0xFFFFFFFFFFFFFF);
      _decisionCache->set(identifier, val, 0);
      break;
    }
    default: break;
  }
  // TODO(rah): Look at a replacement for wakeup(), maybe NSCondition
}

- (BOOL)flushCacheNonRootOnly:(BOOL)nonRootOnly API_AVAILABLE(macos(10.15)) {
  _decisionCache->clear();
  if (!self.connectionEstablished) return YES;  // if not connected, there's nothing to flush.
  return es_clear_cache(self.client) == ES_CLEAR_CACHE_RESULT_SUCCESS;
}

- (NSArray<NSNumber *> *)cacheCounts {
  return @[ @(_decisionCache->count()), @(0) ];
}

- (NSArray<NSNumber *> *)cacheBucketCount {
  // TODO: add this, maybe.
  return nil;
}

- (santa_action_t)checkCache:(santa_vnode_id_t)vnodeID {
  auto result = ACTION_UNSET;
  uint64_t decision_time = 0;

  uint64_t cache_val = _decisionCache->get(vnodeID);
  if (cache_val == 0) return result;

  // Decision is stored in upper 8 bits, timestamp in remaining 56.
  result = (santa_action_t)(cache_val >> 56);
  decision_time = (cache_val & ~(0xFF00000000000000));

  if (RESPONSE_VALID(result)) {
    if (result == ACTION_RESPOND_DENY) {
      auto expiry_time = decision_time + (500 * 100000);  // kMaxCacheDenyTimeMilliseconds
      if (expiry_time < GetCurrentUptime()) {
        _decisionCache->remove(vnodeID);
        return ACTION_UNSET;
      }
    }
  }
  return result;
}

- (kern_return_t)removeCacheEntryForVnodeID:(santa_vnode_id_t)vnodeID {
  _decisionCache->remove(vnodeID);
  // TODO(rah): Look at a replacement for wakeup(), maybe NSCondition
  return 0;
}

@end
