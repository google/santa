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
#include <sys/wait.h>
#include <uuid/uuid.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/SNTLogging.h"
#include "Source/common/santa_new.pb.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"
#import "Source/santad/SNTDecisionCache.h"

using google::protobuf::Arena;
using google::protobuf::Timestamp;

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedEventType;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFile;
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

static inline void EncodeUUID(pb::SantaMessage *pb_santa_msg, const uuid_t &uuid) {
  uuid_string_t uuid_str;
  uuid_unparse_lower(uuid, uuid_str);
  pb_santa_msg->set_uuid(uuid_str, sizeof(uuid_str) - 1);
}

static inline void EncodeTimestamp(Timestamp *timestamp, struct timespec ts) {
  timestamp->set_seconds(ts.tv_sec);
  timestamp->set_nanos((int32_t)ts.tv_nsec);
}

static inline void EncodeProcessID(pb::ProcessID *proc_id, const audit_token_t &tok) {
  proc_id->set_pid(audit_token_to_pid(tok));
  proc_id->set_pidversion(audit_token_to_pidversion(tok));
}

static inline void EncodeUserInfo(pb::UserInfo *pb_user_info, uid_t uid,
                                  const std::optional<std::shared_ptr<std::string>> &name) {
  pb_user_info->set_uid(uid);
  if (name.has_value()) {
    pb_user_info->set_name(*name->get());
  }
}

static inline void EncodeGroupInfo(pb::GroupInfo *pb_group_info, gid_t gid,
                                   const std::optional<std::shared_ptr<std::string>> &name) {
  pb_group_info->set_gid(gid);
  if (name.has_value()) {
    pb_group_info->set_name(*name->get());
  }
}

static inline void EncodeHash(pb::Hash *pb_hash, NSString *sha256) {
  pb_hash->set_type(pb::Hash::HASH_ALGO_SHA256);
  pb_hash->set_hash([sha256 UTF8String], [sha256 length]);
}

static inline void EncodeStat(pb::Stat *pb_stat, const struct stat &sb,
                              const std::optional<std::shared_ptr<std::string>> &username,
                              const std::optional<std::shared_ptr<std::string>> &groupname) {
  pb_stat->set_dev(sb.st_dev);
  pb_stat->set_mode(sb.st_mode);
  pb_stat->set_nlink(sb.st_nlink);
  pb_stat->set_ino(sb.st_ino);
  EncodeUserInfo(pb_stat->mutable_user(), sb.st_uid, username);
  EncodeGroupInfo(pb_stat->mutable_group(), sb.st_gid, groupname);
  pb_stat->set_rdev(sb.st_rdev);
  EncodeTimestamp(pb_stat->mutable_access_time(), sb.st_atimespec);
  EncodeTimestamp(pb_stat->mutable_modification_time(), sb.st_mtimespec);
  EncodeTimestamp(pb_stat->mutable_change_time(), sb.st_ctimespec);
  EncodeTimestamp(pb_stat->mutable_birth_time(), sb.st_birthtimespec);
  pb_stat->set_size(sb.st_size);
  pb_stat->set_blocks(sb.st_blocks);
  pb_stat->set_blksize(sb.st_blksize);
  pb_stat->set_flags(sb.st_flags);
  pb_stat->set_gen(sb.st_gen);
}

static inline void EncodeFile(pb::File *pb_file, const es_file_t *es_file,
                              const EnrichedFile &enriched_file, NSString *sha256 = nil) {
  pb_file->set_path(es_file->path.data, es_file->path.length);
  pb_file->set_truncated(es_file->path_truncated);
  EncodeStat(pb_file->mutable_stat(), es_file->stat, enriched_file.user(), enriched_file.group());
  if (sha256) {
    EncodeHash(pb_file->mutable_hash(), sha256);
  }
}

static inline void EncodeProcessInfo(pb::ProcessInfo *pb_proc_info, const es_process_t *es_proc,
                                     const EnrichedProcess &enriched_proc,
                                     SNTCachedDecision *cd = nil) {
  EncodeProcessID(pb_proc_info->mutable_id(), es_proc->audit_token);
  EncodeProcessID(pb_proc_info->mutable_parent_id(), es_proc->parent_audit_token);
  EncodeProcessID(pb_proc_info->mutable_responsible_id(), es_proc->responsible_audit_token);

  pb_proc_info->set_original_parent_pid(es_proc->original_ppid);
  pb_proc_info->set_group_id(es_proc->group_id);
  pb_proc_info->set_session_id(es_proc->session_id);

  EncodeUserInfo(pb_proc_info->mutable_effective_user(), audit_token_to_euid(es_proc->audit_token),
                 enriched_proc.effective_user());
  EncodeUserInfo(pb_proc_info->mutable_real_user(), audit_token_to_ruid(es_proc->audit_token),
                 enriched_proc.real_user());
  EncodeGroupInfo(pb_proc_info->mutable_effective_group(),
                  audit_token_to_egid(es_proc->audit_token), enriched_proc.effective_group());
  EncodeGroupInfo(pb_proc_info->mutable_real_group(), audit_token_to_rgid(es_proc->audit_token),
                  enriched_proc.real_group());

  pb_proc_info->set_is_platform_binary(es_proc->is_platform_binary);
  pb_proc_info->set_is_es_client(es_proc->is_es_client);

  if (es_proc->codesigning_flags & CS_SIGNED) {
    pb::CodeSignature *pb_code_sig = pb_proc_info->mutable_code_signature();
    pb_code_sig->set_cdhash(es_proc->cdhash, sizeof(es_proc->cdhash));
    if (es_proc->signing_id.length > 0) {
      pb_code_sig->set_signing_id(es_proc->signing_id.data, es_proc->signing_id.length);
    }

    if (es_proc->team_id.length > 0) {
      pb_code_sig->set_team_id(es_proc->team_id.data, es_proc->team_id.length);
    }
  }

  pb_proc_info->set_cs_flags(es_proc->codesigning_flags);

  EncodeFile(pb_proc_info->mutable_executable(), es_proc->executable, enriched_proc.executable(),
             cd.sha256);
  if (es_proc->tty) {
    // Note: TTY's are not currently enriched. Create an empty enriched file for encoding.
    EnrichedFile enriched_file(std::nullopt, std::nullopt, std::nullopt);
    EncodeFile(pb_proc_info->mutable_tty(), es_proc->tty, enriched_file, nil);
  }
}

void EncodeExitStatus(pb::Exit *pb_exit, int exitStatus) {
  if (WIFEXITED(exitStatus)) {
    pb_exit->mutable_exited()->set_exit_status(WEXITSTATUS(exitStatus));
  } else if (WIFSIGNALED(exitStatus)) {
    pb_exit->mutable_signaled()->set_signal(WTERMSIG(exitStatus));
  } else if (WIFSTOPPED(exitStatus)) {
    pb_exit->mutable_stopped()->set_signal(WSTOPSIG(exitStatus));
  } else {
    LOGE(@"Unknown exit status encountered: %d", exitStatus);
  }
}

void EncodeCertificateInfo(pb::CertificateInfo *pb_cert_info, NSString *cert_hash,
                           NSString *common_name) {
  if (cert_hash) {
    EncodeHash(pb_cert_info->mutable_hash(), cert_hash);
  }

  if (common_name) {
    pb_cert_info->set_common_name([common_name UTF8String], [common_name length]);
  }
}

pb::Execution::Decision GetDecisionEnum(SNTEventState event_state) {
  if (event_state & SNTEventStateAllow) {
    return pb::Execution::DECISION_ALLOW;
  } else if (event_state & SNTEventStateBlock) {
    return pb::Execution::DECISION_DENY;
  } else {
    return pb::Execution::DECISION_UNKNOWN;
  }
}

pb::Execution::Reason GetReasonEnum(SNTEventState event_state) {
  switch (event_state) {
    case SNTEventStateAllowBinary: return pb::Execution::REASON_BINARY;
    case SNTEventStateAllowCompiler: return pb::Execution::REASON_COMPILER;
    case SNTEventStateAllowTransitive: return pb::Execution::REASON_TRANSITIVE;
    case SNTEventStateAllowPendingTransitive: return pb::Execution::REASON_PENDING_TRANSITIVE;
    case SNTEventStateAllowCertificate: return pb::Execution::REASON_CERT;
    case SNTEventStateAllowScope: return pb::Execution::REASON_SCOPE;
    case SNTEventStateAllowTeamID: return pb::Execution::REASON_TEAM_ID;
    case SNTEventStateAllowUnknown: return pb::Execution::REASON_UNKNOWN;
    case SNTEventStateBlockBinary: return pb::Execution::REASON_BINARY;
    case SNTEventStateBlockCertificate: return pb::Execution::REASON_CERT;
    case SNTEventStateBlockScope: return pb::Execution::REASON_SCOPE;
    case SNTEventStateBlockTeamID: return pb::Execution::REASON_TEAM_ID;
    case SNTEventStateBlockLongPath: return pb::Execution::REASON_LONG_PATH;
    case SNTEventStateBlockUnknown: return pb::Execution::REASON_UNKNOWN;
    default: return pb::Execution::REASON_NOT_RUNNING;
  }
}

pb::Execution::Mode GetModeEnum(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor: return pb::Execution::MODE_MONITOR;
    case SNTClientModeLockdown: return pb::Execution::MODE_LOCKDOWN;
    case SNTClientModeUnknown: return pb::Execution::MODE_UNKNOWN;
    default: return pb::Execution::MODE_UNKNOWN;
  }
}

static inline pb::SantaMessage *CreateDefaultProto(Arena *arena, const EnrichedEventType &msg) {
  pb::SantaMessage *santa_msg = Arena::CreateMessage<pb::SantaMessage>(arena);

  EncodeUUID(santa_msg, msg.uuid());
  EncodeTimestamp(santa_msg->mutable_event_time(), msg.es_msg().time);
  EncodeTimestamp(santa_msg->mutable_processed_time(), msg.enrichment_time());

  return santa_msg;
}

static inline std::vector<uint8_t> FinalizeProto(pb::SantaMessage *santa_msg) {
  std::vector<uint8_t> vec(santa_msg->ByteSizeLong());
  santa_msg->SerializeToArray(vec.data(), (int)vec.capacity());
  return vec;
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedClose &msg) {
  Arena arena;
  pb::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  EncodeUUID(santa_msg, msg.uuid());
  EncodeTimestamp(santa_msg->mutable_event_time(), msg.es_msg().time);
  EncodeTimestamp(santa_msg->mutable_processed_time(), msg.enrichment_time());

  pb::Close *pb_close = santa_msg->mutable_close();

  EncodeProcessInfo(pb_close->mutable_instigator(), msg.es_msg().process, msg.instigator());
  EncodeFile(pb_close->mutable_target(), msg.es_msg().event.close.target, msg.target());
  pb_close->set_modified(msg.es_msg().event.close.modified);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExchange &msg) {
  Arena arena;
  pb::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  pb::Exchangedata *pb_exchangedata = santa_msg->mutable_exchangedata();

  EncodeProcessInfo(pb_exchangedata->mutable_instigator(), msg.es_msg().process, msg.instigator());
  EncodeFile(pb_exchangedata->mutable_file1(), msg.es_msg().event.exchangedata.file1, msg.file1());
  EncodeFile(pb_exchangedata->mutable_file2(), msg.es_msg().event.exchangedata.file2, msg.file2());

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExec &msg) {
  Arena arena;
  pb::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  SNTCachedDecision *cd = [[SNTDecisionCache sharedCache]
    cachedDecisionForFile:msg.es_msg().event.exec.target->executable->stat];

  GetDecisionEnum(cd.decision);

  pb::Execution *pb_exec = santa_msg->mutable_execution();

  EncodeProcessInfo(pb_exec->mutable_instigator(), msg.es_msg().process, msg.instigator());
  EncodeProcessInfo(pb_exec->mutable_target(), msg.es_msg().event.exec.target, msg.target());
  if (msg.script().has_value()) {
    EncodeFile(pb_exec->mutable_script(), msg.es_msg().event.exec.script, msg.script().value());
  }

  if (msg.working_dir().has_value()) {
    EncodeFile(pb_exec->mutable_working_directory(), msg.es_msg().event.exec.cwd,
               msg.working_dir().value());
  }

  pb_exec->set_decision(GetDecisionEnum(cd.decision));
  pb_exec->set_reason(GetReasonEnum(cd.decision));
  pb_exec->set_mode(GetModeEnum([[SNTConfigurator configurator] clientMode]));

  if (cd.certSHA256 || cd.certCommonName) {
    EncodeCertificateInfo(pb_exec->mutable_certificate_info(), cd.certSHA256, cd.certCommonName);
  }

  if (cd.decisionExtra) {
    pb_exec->set_explain([cd.decisionExtra UTF8String], [cd.decisionExtra length]);
  }

  // TODO TODO: Thread thru exec file hash...

  if (cd.quarantineURL) {
    pb_exec->set_quarantine_url([cd.quarantineURL UTF8String], [cd.quarantineURL length]);
  }

  NSString *orig_path = Utilities::OriginalPathForTranslocation(msg.es_msg().event.exec.target);
  if (orig_path) {
    pb_exec->set_original_path([orig_path UTF8String], [orig_path length]);
  }

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExit &msg) {
  Arena arena;
  pb::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  pb::Exit *pb_exit = santa_msg->mutable_exit();

  EncodeProcessInfo(pb_exit->mutable_instigator(), msg.es_msg().process, msg.instigator());
  EncodeExitStatus(pb_exit, msg.es_msg().event.exit.stat);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedFork &msg) {
  Arena arena;
  pb::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  pb::Fork *pb_fork = santa_msg->mutable_fork();

  EncodeProcessInfo(pb_fork->mutable_instigator(), msg.es_msg().process, msg.instigator());
  EncodeProcessInfo(pb_fork->mutable_child(), msg.es_msg().event.fork.child, msg.child());

  return FinalizeProto(santa_msg);
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
