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

#import "Source/santad/EventProviders/SNTEndpointSecurityManager.h"
#include "Source/common/SNTPrefixTree.h"

#import "Source/common/SNTLogging.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#import <libproc.h>

@interface SNTEndpointSecurityManager ()

@property(nonatomic) es_client_t *client;
@property(nonatomic) SNTPrefixTree *prefixTree;
@property (nonatomic, copy) void (^decisionCallback)(santa_message_t);
@property (nonatomic, copy) void (^logCallback)(santa_message_t);

@end

@implementation SNTEndpointSecurityManager

- (instancetype)init API_AVAILABLE(macos(10.15)) {
  self = [super init];
  if (self) {
    [self establishClient];
    _prefixTree = new SNTPrefixTree();
  }

  return self;
}

- (void)dealloc API_AVAILABLE(macos(10.15)) {
  if (_prefixTree) delete _prefixTree;
  if (_client) {
    es_unsubscribe_all(_client);
    es_delete_client(_client);
  }
}

- (void)establishClient API_AVAILABLE(macos(10.15)) {
  while (!self.client) {
    es_client_t *client = NULL;
    es_new_client_result_t ret = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
      [self messageHandler:m];
    });

    switch (ret) {
      case ES_NEW_CLIENT_RESULT_SUCCESS:
        LOGI(@"Connected to EndpointSecurity");
        self.client = client;
        return;
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        LOGE(@"Unable to create EndpointSecurity client, not full-disk access permitted");
        LOGE(@"Sleeping for 30s before restarting.");
        sleep(30);
        exit(ret);
      default:
        LOGE(@"Unable to create es client: %d. Sleeping for a minute.", ret);
        sleep(60);
        continue;
    }
  }
}

- (void)messageHandler:(const es_message_t *)m API_AVAILABLE(macos(10.15)) {
  santa_message_t sm = {};

  audit_token_t audit_token = {};
  void (^callback)(santa_message_t);

  switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC: {
//      // TODO(bur/rah): Probably also want to do this for is_es_client.
//      // TODO(bur/rah): Since these events are not evaluated by Santa's pipline they are
//      //                missing bits of information such as SHA256 and REASON. Refactor the
//      //                logging cache.
//      if (m->event.exec.target->is_platform_binary) {
//        LOGD(@"platform binary: %s", sm.path);
//        [self postAction:ACTION_RESPOND_ALLOW forMessage:sm];
//        return;
//      }
      sm.es_message = (void *)es_copy_message(m);
      sm.action = ACTION_REQUEST_BINARY;
      sm.vnode_id.fsid = m->event.exec.target->executable->stat.st_dev;
      sm.vnode_id.fileid = m->event.exec.target->executable->stat.st_ino;
      callback = self.decisionCallback;
      audit_token = m->event.exec.target->audit_token;
      sm.ppid = m->event.exec.target->original_ppid;

      size_t l = m->event.exec.target->executable->path.length;
      if (l + 1 > MAXPATHLEN ||  m->event.exec.target->executable->path_truncated) {
        // TODO(bur/rah): Get path from fsid.
        LOGE(@"Path is truncated!");
        es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, true);
        return;
      }
      strncpy(sm.path,m->event.exec.target->executable->path.data, l);
      sm.path[l] = '\0';

      break;
    }
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
      sm.action = ACTION_NOTIFY_EXEC;
      sm.vnode_id.fsid = m->event.exec.target->executable->stat.st_dev;
      sm.vnode_id.fileid = m->event.exec.target->executable->stat.st_ino;

      // TODO(rah): Profile this, it might need to be improved.
      uint32_t argCount = es_exec_arg_count(&(m->event.exec));
      NSMutableArray *args = [NSMutableArray arrayWithCapacity:argCount];
      for (int i = 0; i < argCount; ++i) {
        es_string_token_t arg = es_exec_arg(&(m->event.exec), i);
        [args addObject:[[NSString alloc] initWithBytes:arg.data
                                                 length:arg.length
                                               encoding:NSUTF8StringEncoding]];
      }
      sm.args_array = (void *)CFBridgingRetain(args);

      callback = self.logCallback;
      audit_token = m->event.exec.target->audit_token;
      sm.ppid = m->event.exec.target->original_ppid;

      size_t l = m->event.exec.target->executable->path.length;
      strncpy(sm.path,m->event.exec.target->executable->path.data, l);
      sm.path[l] = '\0';

      break;
    }
    case ES_EVENT_TYPE_NOTIFY_CLOSE: {
      if (!m->event.close.modified) return;
      sm.action = ACTION_NOTIFY_WRITE;
      sm.ppid = m->process->original_ppid;
      strncpy(sm.path, m->event.close.target->path.data, m->event.close.target->path.length);
      sm.path[m->event.close.target->path.length] = '\0';
      callback = self.logCallback;
      audit_token = m->process->audit_token;
      break;
    }
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
      sm.action = ACTION_NOTIFY_DELETE;
      sm.ppid = m->process->original_ppid;
      strncpy(sm.path, m->event.unlink.target->path.data, m->event.unlink.target->path.length);
      sm.path[m->event.unlink.target->path.length] = '\0';
      callback = self.logCallback;
      audit_token = m->process->audit_token;
    case ES_EVENT_TYPE_NOTIFY_TRUNCATE: {
      sm.action = ACTION_NOTIFY_DELETE;
      sm.ppid = m->process->original_ppid;
      strncpy(sm.path, m->event.truncate.target->path.data, m->event.truncate.target->path.length);
      sm.path[m->event.truncate.target->path.length] = '\0';
      callback = self.logCallback;
      audit_token = m->process->audit_token;
      break;
    }
    case ES_EVENT_TYPE_NOTIFY_LINK: {
      sm.action = ACTION_NOTIFY_LINK;
      sm.ppid = m->process->original_ppid;
      strncpy(sm.path, m->event.link.source->path.data, m->event.link.source->path.length);
      sm.path[m->event.link.source->path.length] = '\0';
      strncpy(sm.newpath, m->event.link.target_filename.data, m->event.link.target_filename.length);
      sm.newpath[m->event.link.target_filename.length] = '\0';
      callback = self.logCallback;
      audit_token = m->process->audit_token;
      break;
    }
    case ES_EVENT_TYPE_NOTIFY_RENAME: {
      sm.action = ACTION_NOTIFY_RENAME;
      sm.ppid = m->process->original_ppid;
      strncpy(sm.path, m->event.rename.source->path.data, m->event.rename.source->path.length);
      sm.path[m->event.rename.source->path.length] = '\0';

      switch(m->event.rename.destination_type) {
        case ES_DESTINATION_TYPE_NEW_PATH:
          strncpy(sm.newpath, m->event.rename.destination.new_path.filename.data, m->event.rename.destination.new_path.filename.length);
          sm.newpath[m->event.rename.destination.new_path.filename.length] = '\0';
          break;
        case ES_DESTINATION_TYPE_EXISTING_FILE:
          strncpy(sm.newpath, m->event.rename.destination.existing_file->path.data, m->event.rename.destination.existing_file->path.length);
          sm.newpath[m->event.rename.destination.existing_file->path.length] = '\0';
          break;
      }

      callback = self.logCallback;
      audit_token = m->process->audit_token;
    }
    default:
      break;
  }

  if (self.prefixTree->HasPrefix(sm.path)) {
    return;
  }

  if (callback) {
    sm.uid = audit_token_to_ruid(audit_token);
    sm.gid = audit_token_to_rgid(audit_token);
    sm.pid = audit_token_to_pid(audit_token);
    proc_name(sm.pid, sm.pname, 1024);
    callback(sm);
  }
}

- (void)listenForDecisionRequests:(void (^)(santa_message_t))callback API_AVAILABLE(macos(10.15)) {
  while (!self.connectionEstablished) usleep(100000); // 100ms

  // Listen for exec auth messages.
  self.decisionCallback = callback;
  es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
  es_return_t sret = es_subscribe(self.client, events, 1);
  if (sret != ES_RETURN_SUCCESS) LOGE(@"Unable to subscribe ES_EVENT_TYPE_AUTH_EXEC: %d", sret);

  // There's a gap between creating a client and subscribing to events. Creating the client
  // triggers a cache flush automatically but any events that happen in this gap could be allowed
  // and cached, so we force the cache to flush again.
  [self flushCacheNonRootOnly:YES];
}

- (void)listenForLogRequests:(void (^)(santa_message_t))callback API_AVAILABLE(macos(10.15)) {
  while (!self.connectionEstablished) usleep(100000); // 100ms

  // Listen for exec notify messages.
  self.logCallback = callback;
  es_event_type_t events[] = {
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_CLOSE,
    ES_EVENT_TYPE_NOTIFY_TRUNCATE,
    ES_EVENT_TYPE_NOTIFY_LINK,
    ES_EVENT_TYPE_NOTIFY_RENAME,
    ES_EVENT_TYPE_NOTIFY_UNLINK,
  };
  es_return_t sret = es_subscribe(self.client, events, sizeof(events) / sizeof(es_event_type_t));
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
      ret = ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
  }

  if (sm.es_message) {
    es_free_message((es_message_t *)sm.es_message);
    sm.es_message = NULL;
  }

  return ret;
}

- (BOOL)flushCacheNonRootOnly:(BOOL)nonRootOnly API_AVAILABLE(macos(10.15)) {
  if (!self.connectionEstablished) return YES; // if not connected, there's nothing to flush.
  return es_clear_cache(self.client) == ES_CLEAR_CACHE_RESULT_SUCCESS;
}

- (void)fileModificationPrefixFilterAdd:(NSArray *)filters {
  for (NSString *filter in filters) {
    self.prefixTree->AddPrefix(filter.fileSystemRepresentation);
  }
}

- (void)fileModificationPrefixFilterReset {
  self.prefixTree->Reset();
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
