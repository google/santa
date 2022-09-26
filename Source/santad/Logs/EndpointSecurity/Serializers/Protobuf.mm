/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"

#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>
#include <google/protobuf/arena.h>
#include <mach/message.h>
#include <uuid/uuid.h>

#include "Source/common/SNTCachedDecision.h"
#include "Source/common/santa_new.pb.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

using google::protobuf::Arena;
using google::protobuf::Timestamp;

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedLink;
using santa::santad::event_providers::endpoint_security::EnrichedProcess;
using santa::santad::event_providers::endpoint_security::EnrichedRename;
using santa::santad::event_providers::endpoint_security::EnrichedUnlink;
using santa::santad::event_providers::endpoint_security::Message;

namespace santa::santad::logs::endpoint_security::serializers {

std::shared_ptr<Protobuf> Protobuf::Create(std::shared_ptr<EndpointSecurityAPI> esapi) {
  return std::make_shared<Protobuf>(esapi);
}

Protobuf::Protobuf(std::shared_ptr<EndpointSecurityAPI> esapi) : esapi_(esapi) {}

static inline pb::SantaMessage *CreateDefaultProto(Arena *arena) {
  return Arena::CreateMessage<pb::SantaMessage>(arena);
}

static inline std::vector<uint8_t> FinalizeProto(pb::SantaMessage *santa_msg) {
  std::vector<uint8_t> vec(santa_msg->ByteSizeLong());
  santa_msg->SerializeToArray(vec.data(), (int)vec.capacity());
  return vec;
}

static inline void EncodeUUID(pb::SantaMessage *santa_msg, const uuid_t &uuid) {
  uuid_string_t uuid_str;
  uuid_unparse_lower(uuid, uuid_str);
  santa_msg->set_uuid(uuid_str, sizeof(uuid_str) - 1);
}

static inline void EncodeTimestamp(Timestamp *timestamp, struct timespec ts) {
  timestamp->set_seconds(ts.tv_sec);
  timestamp->set_nanos((int32_t)ts.tv_nsec);
}

static inline void EncodeProcessID(pb::ProcessID *proc_id, const audit_token_t &tok) {
  proc_id->set_pid(audit_token_to_pid(tok));
  proc_id->set_pidversion(audit_token_to_pidversion(tok));
}

static inline void EncodeUserInfo(pb::UserInfo *user_info, uid_t uid,
                                  const std::optional<std::shared_ptr<std::string>> &name) {
  user_info->set_uid(uid);
  if (name.has_value()) {
    user_info->set_name(*name->get());
  }
}

static inline void EncodeGroupInfo(pb::GroupInfo *group_info, gid_t uid,
                                   const std::optional<std::shared_ptr<std::string>> &name) {
  group_info->set_gid(uid);
  if (name.has_value()) {
    group_info->set_name(*name->get());
  }
}

static inline void EncodeHash(pb::Hash *hash, NSString *sha256) {
  hash->set_type(pb::Hash::HASH_ALGO_SHA256);
  hash->set_hash([sha256 UTF8String], [sha256 length]);
}

static inline void EncodeStat(pb::Stat *stat, const struct stat &sb) {
  stat->set_dev(sb.st_dev);
  stat->set_mode(sb.st_mode);
  stat->set_nlink(sb.st_nlink);
  stat->set_ino(sb.st_ino);
  stat->set_rdev(sb.st_rdev);
  EncodeTimestamp(stat->mutable_access_time(), sb.st_atimespec);
  EncodeTimestamp(stat->mutable_modification_time(), sb.st_mtimespec);
  EncodeTimestamp(stat->mutable_change_time(), sb.st_ctimespec);
  EncodeTimestamp(stat->mutable_birth_time(), sb.st_birthtimespec);
  stat->set_size(sb.st_size);
  stat->set_blocks(sb.st_blocks);
  stat->set_blksize(sb.st_blksize);
  stat->set_flags(sb.st_flags);
  stat->set_gen(sb.st_gen);
}

static inline void EncodeFile(pb::File *file, const es_file_t *es_file, NSString *sha256 = nil) {
  file->set_path(es_file->path.data, es_file->path.length);
  file->set_truncated(es_file->path_truncated);
  EncodeStat(file->mutable_stat(), es_file->stat);
  if (sha256) {
    EncodeHash(file->mutable_hash(), sha256);
  }
}

static inline void EncodeProcessInfo(pb::ProcessInfo *proc_info, const es_process_t *es_proc,
                                     const EnrichedProcess &enriched_proc,
                                     SNTCachedDecision *cd = nil) {
  EncodeProcessID(proc_info->mutable_id(), es_proc->audit_token);
  EncodeProcessID(proc_info->mutable_parent_id(), es_proc->parent_audit_token);
  EncodeProcessID(proc_info->mutable_responsible_id(), es_proc->responsible_audit_token);

  proc_info->set_original_parent_pid(es_proc->original_ppid);
  proc_info->set_group_id(es_proc->group_id);
  proc_info->set_session_id(es_proc->session_id);

  EncodeUserInfo(proc_info->mutable_effective_user(), audit_token_to_euid(es_proc->audit_token),
                 enriched_proc.effective_user());
  EncodeUserInfo(proc_info->mutable_real_user(), audit_token_to_ruid(es_proc->audit_token),
                 enriched_proc.real_user());
  EncodeGroupInfo(proc_info->mutable_effective_group(), audit_token_to_egid(es_proc->audit_token),
                  enriched_proc.effective_group());
  EncodeGroupInfo(proc_info->mutable_real_group(), audit_token_to_rgid(es_proc->audit_token),
                  enriched_proc.real_group());

  proc_info->set_is_platform_binary(es_proc->is_platform_binary);
  proc_info->set_is_es_client(es_proc->is_es_client);

  if (es_proc->codesigning_flags & CS_SIGNED) {
    pb::CodeSignature *code_sig = proc_info->mutable_code_signature();
    code_sig->set_cdhash(es_proc->cdhash, sizeof(es_proc->cdhash));
    if (es_proc->signing_id.length > 0) {
      code_sig->set_signing_id(es_proc->signing_id.data, es_proc->signing_id.length);
    }

    if (es_proc->team_id.length > 0) {
      code_sig->set_team_id(es_proc->team_id.data, es_proc->team_id.length);
    }
  }

  proc_info->set_cs_flags(es_proc->codesigning_flags);

  EncodeFile(proc_info->mutable_executable(), es_proc->executable, cd.sha256);
  if (es_proc->tty) {
    EncodeFile(proc_info->mutable_tty(), es_proc->tty, nil);
  }
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedClose &msg) {
  Arena arena;
  pb::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  EncodeUUID(santa_msg, msg.uuid());
  EncodeTimestamp(santa_msg->mutable_event_time(), msg.es_msg().time);
  EncodeTimestamp(santa_msg->mutable_processed_time(), msg.enrichment_time());

  pb::Close *close = santa_msg->mutable_close();

  EncodeProcessInfo(close->mutable_instigator(), msg.es_msg().process, msg.instigator());
  EncodeFile(close->mutable_target(), msg.es_msg().event.close.target);
  close->set_modified(msg.es_msg().event.close.modified);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExchange &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExec &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExit &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedFork &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLink &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedRename &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedUnlink &msg) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeAllowlist(const Message &msg, const std::string_view hash) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeBundleHashingEvent(SNTStoredEvent *event) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeDiskAppeared(NSDictionary *props) {
  return {};
}

std::vector<uint8_t> Protobuf::SerializeDiskDisappeared(NSDictionary *props) {
  return {};
}

}  // namespace santa::santad::logs::endpoint_security::serializers
