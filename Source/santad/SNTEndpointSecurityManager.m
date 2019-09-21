/// Copyright 2019 Google Inc. All rights reserved.
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

#import "Source/santad/SNTEndpointSecurityManager.h"

#import "Source/common/SNTLogging.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

@interface SNTEndpointSecurityManager ()

@property(nonatomic) es_client_t *client;
@property (nonatomic, copy) void (^decisionCallback)(santa_message_t);
@property (nonatomic, copy) void (^logCallback)(santa_message_t);

@end

@implementation SNTEndpointSecurityManager

- (instancetype)init API_AVAILABLE(macos(10.15)) {
  self = [super init];
  if (self) {
    es_client_t *client = NULL;
    es_new_client_result_t ret = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
      [self messageHandler:m];
    });

    if (ret != ES_NEW_CLIENT_RESULT_SUCCESS) LOGE(@"Unable to create es client: %d", ret);
    self.client = client;
  }

  return self;
}

- (void)messageHandler:(const es_message_t *)m API_AVAILABLE(macos(10.15)) {
  // TODO(bur/rah): Currently this class only subscribes to exec events. Move this code
  // somewhere exec specific if other types of events are added to this client.
  santa_message_t sm;
  sm.uid = audit_token_to_ruid(m->event.exec.target->audit_token);
  sm.gid = audit_token_to_rgid(m->event.exec.target->audit_token);
  sm.pid = audit_token_to_pid(m->event.exec.target->audit_token);
  // original_ppid stays constant even in the event a process is reparented
  sm.ppid = m->event.exec.target->original_ppid;
  sm.es_message = (void *)es_copy_message(m);

  sm.vnode_id.fsid = m->event.exec.target->executable->stat.st_dev;
  sm.vnode_id.fileid = m->event.exec.target->executable->stat.st_ino;

  size_t l = m->event.exec.target->executable->path.length;
  if (l + 1 > MAXPATHLEN ||  m->event.exec.target->executable->path_truncated) {
    // TODO(bur/rah): Get path from fsid.
    LOGE(@"Path is truncated!");
    es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, true);
    return;
  }
  strncpy(sm.path,m->event.exec.target->executable->path.data, l);
  sm.path[l] = '\0';

  switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
//      // TODO(bur/rah): Probably also want to do this for is_es_client.
//      // TODO(bur/rah): Since these events are not evaluated by Santa's pipline they are
//      //                missing bits of information such as SHA256 and REASON. Refactor the
//      //                logging cache.
//      if (m->event.exec.target->is_platform_binary) {
//        LOGD(@"platform binary: %s", sm.path);
//        [self postAction:ACTION_RESPOND_ALLOW forMessage:sm];
//        return;
//      }
      sm.action = ACTION_REQUEST_BINARY;
      if (self.decisionCallback) self.decisionCallback(sm);
      break;
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      sm.action = ACTION_NOTIFY_EXEC;
      if (self.logCallback) self.logCallback(sm);
      break;
    default:
      break;
  }
}

- (void)listenForDecisionRequests:(void (^)(santa_message_t))callback API_AVAILABLE(macos(10.15)) {
  // Listen for exec auth messages.
  self.decisionCallback = callback;
  es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
  es_return_t sret = es_subscribe(self.client, events, 1);
  if (sret != ES_RETURN_SUCCESS) LOGE(@"Unable to subscribe ES_EVENT_TYPE_AUTH_EXEC: %d", sret);

}

- (void)listenForLogRequests:(void (^)(santa_message_t))callback API_AVAILABLE(macos(10.15)) {
  // Listen for exec notify messages.
  self.logCallback = callback;
  es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
  es_return_t sret = es_subscribe(self.client, events, 1);
  if (sret != ES_RETURN_SUCCESS) LOGE(@"Unable to subscribe ES_EVENT_TYPE_NOTIFY_EXEC: %d", sret);
}

- (int)postAction:(santa_action_t)action forMessage:(santa_message_t)sm
    API_AVAILABLE(macos(10.15)) {
  es_respond_result_t ret;
  switch (action) {
    case ACTION_RESPOND_ALLOW:
      ret = es_respond_auth_result(self.client, (es_message_t *)sm.es_message,
                                   ES_AUTH_RESULT_ALLOW, true);
      break;
    case ACTION_RESPOND_DENY:
      ret = es_respond_auth_result(self.client, (es_message_t *)sm.es_message,
                                   ES_AUTH_RESULT_DENY, false);
      break;
    default:
      return ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
  }

  if (sm.es_message) {
    es_free_message(sm.es_message);
    sm.es_message = NULL;
  }

  return ret;
}

- (BOOL)flushCacheNonRootOnly:(BOOL)nonRootOnly API_AVAILABLE(macos(10.15)) {
  return es_clear_cache(self.client) == ES_CLEAR_CACHE_RESULT_SUCCESS;
}

- (void)fileModificationPrefixFilterAdd:(NSArray *)filters {
}

- (void)fileModificationPrefixFilterReset {
}

- (NSArray<NSNumber *> *)cacheCounts {
  return nil;
}

- (NSArray<NSNumber *> *)cacheBucketCount {
  return nil;
}

- (santa_action_t)checkCache:(santa_vnode_id_t)vnodeID {
  return ACTION_UNSET;
}

- (kern_return_t)removeCacheEntryForVnodeID:(santa_vnode_id_t)vnodeId {
  return KERN_FAILURE;
}

- (BOOL)connectionEstablished {
  return self.client != nil;
}

@end
