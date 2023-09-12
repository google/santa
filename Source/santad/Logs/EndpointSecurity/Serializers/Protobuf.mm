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

#include <EndpointSecurity/EndpointSecurity.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>
#include <google/protobuf/json/json.h>
#include <mach/message.h>
#include <math.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <time.h>

#include <functional>
#include <optional>
#include <string_view>

#import "Source/common/SNTCachedDecision.h"
#include "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/String.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"
#import "Source/santad/SNTDecisionCache.h"
#include "absl/status/status.h"
#include "google/protobuf/timestamp.pb.h"

using google::protobuf::Arena;
using google::protobuf::Timestamp;
using JsonPrintOptions = google::protobuf::json::PrintOptions;
using google::protobuf::json::MessageToJsonString;

using santa::common::NSStringToUTF8StringView;
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
using santa::santad::logs::endpoint_security::serializers::Utilities::EffectiveGroup;
using santa::santad::logs::endpoint_security::serializers::Utilities::EffectiveUser;
using santa::santad::logs::endpoint_security::serializers::Utilities::MountFromName;
using santa::santad::logs::endpoint_security::serializers::Utilities::NonNull;
using santa::santad::logs::endpoint_security::serializers::Utilities::Pid;
using santa::santad::logs::endpoint_security::serializers::Utilities::Pidversion;
using santa::santad::logs::endpoint_security::serializers::Utilities::RealGroup;
using santa::santad::logs::endpoint_security::serializers::Utilities::RealUser;

namespace pbv1 = ::santa::pb::v1;

namespace santa::santad::logs::endpoint_security::serializers {

std::shared_ptr<Protobuf> Protobuf::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                           SNTDecisionCache *decision_cache, bool json) {
  return std::make_shared<Protobuf>(esapi, std::move(decision_cache), json);
}

Protobuf::Protobuf(std::shared_ptr<EndpointSecurityAPI> esapi, SNTDecisionCache *decision_cache,
                   bool json)
    : Serializer(std::move(decision_cache)), esapi_(esapi), json_(json) {}

static inline void EncodeTimestamp(Timestamp *timestamp, struct timespec ts) {
  timestamp->set_seconds(ts.tv_sec);
  timestamp->set_nanos((int32_t)ts.tv_nsec);
}

static inline void EncodeTimestamp(Timestamp *timestamp, struct timeval tv) {
  EncodeTimestamp(timestamp, (struct timespec){tv.tv_sec, tv.tv_usec * 1000});
}

static inline void EncodeProcessID(pbv1::ProcessID *proc_id, const audit_token_t &tok) {
  proc_id->set_pid(Pid(tok));
  proc_id->set_pidversion(Pidversion(tok));
}

static inline void EncodePath(std::string *buf, const es_file_t *dir,
                              const es_string_token_t file) {
  buf->append(std::string_view(dir->path.data, dir->path.length));
  buf->append("/");
  buf->append(std::string_view(file.data, file.length));
}

static inline void EncodePath(std::string *buf, const es_file_t *es_file) {
  buf->append(std::string_view(es_file->path.data, es_file->path.length));
}

static inline void EncodeString(std::function<std::string *()> lazy_f, NSString *value) {
  if (value) {
    lazy_f()->append(NSStringToUTF8StringView(value));
  }
}

static inline void EncodeString(std::function<std::string *()> lazy_f, std::string_view value) {
  if (value.length() > 0) {
    lazy_f()->append(value);
  }
}

static inline void EncodeUserInfo(::pbv1::UserInfo *pb_user_info, uid_t uid,
                                  const std::optional<std::shared_ptr<std::string>> &name) {
  pb_user_info->set_uid(uid);
  if (name.has_value()) {
    pb_user_info->set_name(*name->get());
  }
}

static inline void EncodeGroupInfo(::pbv1::GroupInfo *pb_group_info, gid_t gid,
                                   const std::optional<std::shared_ptr<std::string>> &name) {
  pb_group_info->set_gid(gid);
  if (name.has_value()) {
    pb_group_info->set_name(*name->get());
  }
}

static inline void EncodeHash(::pbv1::Hash *pb_hash, NSString *sha256) {
  if (sha256) {
    pb_hash->set_type(::pbv1::Hash::HASH_ALGO_SHA256);
    EncodeString([pb_hash] { return pb_hash->mutable_hash(); }, sha256);
  }
}

static inline void EncodeStat(::pbv1::Stat *pb_stat, const struct stat &sb,
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

static inline void EncodeFileInfo(::pbv1::FileInfo *pb_file, const es_file_t *es_file,
                                  const EnrichedFile &enriched_file, NSString *sha256 = nil) {
  EncodePath(pb_file->mutable_path(), es_file);
  pb_file->set_truncated(es_file->path_truncated);
  EncodeStat(pb_file->mutable_stat(), es_file->stat, enriched_file.user(), enriched_file.group());
  if (sha256) {
    EncodeHash(pb_file->mutable_hash(), sha256);
  }
}

static inline void EncodeFileInfoLight(::pbv1::FileInfoLight *pb_file, std::string_view path,
                                       bool truncated) {
  EncodeString([pb_file] { return pb_file->mutable_path(); }, path);
  pb_file->set_truncated(truncated);
}

static inline void EncodeFileInfoLight(::pbv1::FileInfoLight *pb_file, const es_file_t *es_file) {
  EncodePath(pb_file->mutable_path(), es_file);
  pb_file->set_truncated(es_file->path_truncated);
}

static inline void EncodeProcessInfoLight(::pbv1::ProcessInfoLight *pb_proc_info,
                                          uint32_t message_version, const es_process_t *es_proc,
                                          const EnrichedProcess &enriched_proc) {
  EncodeProcessID(pb_proc_info->mutable_id(), es_proc->audit_token);
  EncodeProcessID(pb_proc_info->mutable_parent_id(), es_proc->parent_audit_token);

  pb_proc_info->set_original_parent_pid(es_proc->original_ppid);
  pb_proc_info->set_group_id(es_proc->group_id);
  pb_proc_info->set_session_id(es_proc->session_id);

  EncodeUserInfo(pb_proc_info->mutable_effective_user(), EffectiveUser(es_proc->audit_token),
                 enriched_proc.effective_user());
  EncodeUserInfo(pb_proc_info->mutable_real_user(), RealUser(es_proc->audit_token),
                 enriched_proc.real_user());
  EncodeGroupInfo(pb_proc_info->mutable_effective_group(), EffectiveGroup(es_proc->audit_token),
                  enriched_proc.effective_group());
  EncodeGroupInfo(pb_proc_info->mutable_real_group(), RealGroup(es_proc->audit_token),
                  enriched_proc.real_group());

  EncodeFileInfoLight(pb_proc_info->mutable_executable(), es_proc->executable);
}

static inline void EncodeProcessInfo(::pbv1::ProcessInfo *pb_proc_info, uint32_t message_version,
                                     const es_process_t *es_proc,
                                     const EnrichedProcess &enriched_proc,
                                     SNTCachedDecision *cd = nil) {
  EncodeProcessID(pb_proc_info->mutable_id(), es_proc->audit_token);
  EncodeProcessID(pb_proc_info->mutable_parent_id(), es_proc->parent_audit_token);
  if (message_version >= 4) {
    EncodeProcessID(pb_proc_info->mutable_responsible_id(), es_proc->responsible_audit_token);
  }

  pb_proc_info->set_original_parent_pid(es_proc->original_ppid);
  pb_proc_info->set_group_id(es_proc->group_id);
  pb_proc_info->set_session_id(es_proc->session_id);

  EncodeUserInfo(pb_proc_info->mutable_effective_user(), EffectiveUser(es_proc->audit_token),
                 enriched_proc.effective_user());
  EncodeUserInfo(pb_proc_info->mutable_real_user(), RealUser(es_proc->audit_token),
                 enriched_proc.real_user());
  EncodeGroupInfo(pb_proc_info->mutable_effective_group(), EffectiveGroup(es_proc->audit_token),
                  enriched_proc.effective_group());
  EncodeGroupInfo(pb_proc_info->mutable_real_group(), RealGroup(es_proc->audit_token),
                  enriched_proc.real_group());

  pb_proc_info->set_is_platform_binary(es_proc->is_platform_binary);
  pb_proc_info->set_is_es_client(es_proc->is_es_client);

  if (es_proc->codesigning_flags & CS_SIGNED) {
    ::pbv1::CodeSignature *pb_code_sig = pb_proc_info->mutable_code_signature();
    pb_code_sig->set_cdhash(es_proc->cdhash, sizeof(es_proc->cdhash));
    if (es_proc->signing_id.length > 0) {
      pb_code_sig->set_signing_id(es_proc->signing_id.data, es_proc->signing_id.length);
    }

    if (es_proc->team_id.length > 0) {
      pb_code_sig->set_team_id(es_proc->team_id.data, es_proc->team_id.length);
    }
  }

  pb_proc_info->set_cs_flags(es_proc->codesigning_flags);

  EncodeFileInfo(pb_proc_info->mutable_executable(), es_proc->executable,
                 enriched_proc.executable(), cd.sha256);
  if (message_version >= 2 && es_proc->tty) {
    EncodeFileInfoLight(pb_proc_info->mutable_tty(), es_proc->tty);
  }

  if (message_version >= 3) {
    EncodeTimestamp(pb_proc_info->mutable_start_time(), es_proc->start_time);
  }
}

void EncodeExitStatus(::pbv1::Exit *pb_exit, int exitStatus) {
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

static inline void EncodeCertificateInfo(::pbv1::CertificateInfo *pb_cert_info, NSString *cert_hash,
                                         NSString *common_name) {
  if (cert_hash) {
    EncodeHash(pb_cert_info->mutable_hash(), cert_hash);
  }

  EncodeString([pb_cert_info] { return pb_cert_info->mutable_common_name(); }, common_name);
}

::pbv1::Execution::Decision GetDecisionEnum(SNTEventState event_state) {
  if (event_state & SNTEventStateAllow) {
    return ::pbv1::Execution::DECISION_ALLOW;
  } else if (event_state & SNTEventStateBlock) {
    return ::pbv1::Execution::DECISION_DENY;
  } else {
    return ::pbv1::Execution::DECISION_UNKNOWN;
  }
}

::pbv1::Execution::Reason GetReasonEnum(SNTEventState event_state) {
  switch (event_state) {
    case SNTEventStateAllowBinary: return ::pbv1::Execution::REASON_BINARY;
    case SNTEventStateAllowCompiler: return ::pbv1::Execution::REASON_COMPILER;
    case SNTEventStateAllowTransitive: return ::pbv1::Execution::REASON_TRANSITIVE;
    case SNTEventStateAllowPendingTransitive: return ::pbv1::Execution::REASON_PENDING_TRANSITIVE;
    case SNTEventStateAllowCertificate: return ::pbv1::Execution::REASON_CERT;
    case SNTEventStateAllowScope: return ::pbv1::Execution::REASON_SCOPE;
    case SNTEventStateAllowTeamID: return ::pbv1::Execution::REASON_TEAM_ID;
    case SNTEventStateAllowSigningID: return ::pbv1::Execution::REASON_SIGNING_ID;
    case SNTEventStateAllowUnknown: return ::pbv1::Execution::REASON_UNKNOWN;
    case SNTEventStateBlockBinary: return ::pbv1::Execution::REASON_BINARY;
    case SNTEventStateBlockCertificate: return ::pbv1::Execution::REASON_CERT;
    case SNTEventStateBlockScope: return ::pbv1::Execution::REASON_SCOPE;
    case SNTEventStateBlockTeamID: return ::pbv1::Execution::REASON_TEAM_ID;
    case SNTEventStateBlockSigningID: return ::pbv1::Execution::REASON_SIGNING_ID;
    case SNTEventStateBlockLongPath: return ::pbv1::Execution::REASON_LONG_PATH;
    case SNTEventStateBlockUnknown: return ::pbv1::Execution::REASON_UNKNOWN;
    default: return ::pbv1::Execution::REASON_NOT_RUNNING;
  }
}

::pbv1::Execution::Mode GetModeEnum(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor: return ::pbv1::Execution::MODE_MONITOR;
    case SNTClientModeLockdown: return ::pbv1::Execution::MODE_LOCKDOWN;
    case SNTClientModeUnknown: return ::pbv1::Execution::MODE_UNKNOWN;
    default: return ::pbv1::Execution::MODE_UNKNOWN;
  }
}

::pbv1::FileDescriptor::FDType GetFileDescriptorType(uint32_t fdtype) {
  switch (fdtype) {
    case PROX_FDTYPE_ATALK: return ::pbv1::FileDescriptor::FD_TYPE_ATALK;
    case PROX_FDTYPE_VNODE: return ::pbv1::FileDescriptor::FD_TYPE_VNODE;
    case PROX_FDTYPE_SOCKET: return ::pbv1::FileDescriptor::FD_TYPE_SOCKET;
    case PROX_FDTYPE_PSHM: return ::pbv1::FileDescriptor::FD_TYPE_PSHM;
    case PROX_FDTYPE_PSEM: return ::pbv1::FileDescriptor::FD_TYPE_PSEM;
    case PROX_FDTYPE_KQUEUE: return ::pbv1::FileDescriptor::FD_TYPE_KQUEUE;
    case PROX_FDTYPE_PIPE: return ::pbv1::FileDescriptor::FD_TYPE_PIPE;
    case PROX_FDTYPE_FSEVENTS: return ::pbv1::FileDescriptor::FD_TYPE_FSEVENTS;
    case PROX_FDTYPE_NETPOLICY: return ::pbv1::FileDescriptor::FD_TYPE_NETPOLICY;
    // Note: CHANNEL and NEXUS types weren't exposed until Xcode v13 SDK.
    // Not using the macros to be able to build on older SDK versions.
    case 10 /* PROX_FDTYPE_CHANNEL */: return ::pbv1::FileDescriptor::FD_TYPE_CHANNEL;
    case 11 /* PROX_FDTYPE_NEXUS */: return ::pbv1::FileDescriptor::FD_TYPE_NEXUS;
    default: return ::pbv1::FileDescriptor::FD_TYPE_UNKNOWN;
  }
}

::pbv1::FileAccess::AccessType GetAccessType(es_event_type_t event_type) {
  switch (event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE: return ::pbv1::FileAccess::ACCESS_TYPE_CLONE;
    case ES_EVENT_TYPE_AUTH_CREATE: return ::pbv1::FileAccess::ACCESS_TYPE_CREATE;
    case ES_EVENT_TYPE_AUTH_COPYFILE: return ::pbv1::FileAccess::ACCESS_TYPE_COPYFILE;
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA: return ::pbv1::FileAccess::ACCESS_TYPE_EXCHANGEDATA;
    case ES_EVENT_TYPE_AUTH_LINK: return ::pbv1::FileAccess::ACCESS_TYPE_LINK;
    case ES_EVENT_TYPE_AUTH_OPEN: return ::pbv1::FileAccess::ACCESS_TYPE_OPEN;
    case ES_EVENT_TYPE_AUTH_RENAME: return ::pbv1::FileAccess::ACCESS_TYPE_RENAME;
    case ES_EVENT_TYPE_AUTH_TRUNCATE: return ::pbv1::FileAccess::ACCESS_TYPE_TRUNCATE;
    case ES_EVENT_TYPE_AUTH_UNLINK: return ::pbv1::FileAccess::ACCESS_TYPE_UNLINK;
    default: return ::pbv1::FileAccess::ACCESS_TYPE_UNKNOWN;
  }
}

::pbv1::FileAccess::PolicyDecision GetPolicyDecision(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kDenied: return ::pbv1::FileAccess::POLICY_DECISION_DENIED;
    case FileAccessPolicyDecision::kDeniedInvalidSignature:
      return ::pbv1::FileAccess::POLICY_DECISION_DENIED_INVALID_SIGNATURE;
    case FileAccessPolicyDecision::kAllowedAuditOnly:
      return ::pbv1::FileAccess::POLICY_DECISION_ALLOWED_AUDIT_ONLY;
    default: return ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN;
  }
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena, struct timespec event_time,
                                                   struct timespec processed_time) {
  ::pbv1::SantaMessage *santa_msg = Arena::CreateMessage<::pbv1::SantaMessage>(arena);

  if (EnabledMachineID()) {
    EncodeString([santa_msg] { return santa_msg->mutable_machine_id(); }, MachineID());
  }
  EncodeTimestamp(santa_msg->mutable_event_time(), event_time);
  EncodeTimestamp(santa_msg->mutable_processed_time(), processed_time);

  return santa_msg;
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena, const EnrichedEventType &msg) {
  return CreateDefaultProto(arena, msg.es_msg().time, msg.enrichment_time());
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena, const Message &msg) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  return CreateDefaultProto(arena, msg->time, ts);
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  return CreateDefaultProto(arena, ts, ts);
}

std::vector<uint8_t> Protobuf::FinalizeProto(::pbv1::SantaMessage *santa_msg) {
  if (this->json_) {
    // TODO: Profile this. It's probably not the most efficient way to do this.
    JsonPrintOptions options;
    options.always_print_enums_as_ints = false;
    options.always_print_primitive_fields = true;
    options.preserve_proto_field_names = true;
    std::string json;

    absl::Status status = MessageToJsonString(*santa_msg, &json, options);

    if (!status.ok()) {
      LOGE(@"Failed to convert protobuf to JSON: %s", status.ToString().c_str());
    }

    std::vector<uint8_t> vec(json.begin(), json.end());
    // Add a newline to the end of the JSON row.
    vec.push_back('\n');
    return vec;
  }

  std::vector<uint8_t> vec(santa_msg->ByteSizeLong());
  santa_msg->SerializeWithCachedSizesToArray(vec.data());
  return vec;
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedClose &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Close *pb_close = santa_msg->mutable_close();

  EncodeProcessInfoLight(pb_close->mutable_instigator(), msg.es_msg().version, msg.es_msg().process,
                         msg.instigator());
  EncodeFileInfo(pb_close->mutable_target(), msg.es_msg().event.close.target, msg.target());
  pb_close->set_modified(msg.es_msg().event.close.modified);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExchange &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Exchangedata *pb_exchangedata = santa_msg->mutable_exchangedata();

  EncodeProcessInfoLight(pb_exchangedata->mutable_instigator(), msg.es_msg().version,
                         msg.es_msg().process, msg.instigator());
  EncodeFileInfo(pb_exchangedata->mutable_file1(), msg.es_msg().event.exchangedata.file1,
                 msg.file1());
  EncodeFileInfo(pb_exchangedata->mutable_file2(), msg.es_msg().event.exchangedata.file2,
                 msg.file2());

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExec &msg, SNTCachedDecision *cd) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  GetDecisionEnum(cd.decision);

  ::pbv1::Execution *pb_exec = santa_msg->mutable_execution();

  EncodeProcessInfoLight(pb_exec->mutable_instigator(), msg.es_msg().version, msg.es_msg().process,
                         msg.instigator());
  EncodeProcessInfo(pb_exec->mutable_target(), msg.es_msg().version, msg.es_msg().event.exec.target,
                    msg.target(), cd);

  if (msg.es_msg().version >= 2 && msg.script().has_value()) {
    EncodeFileInfo(pb_exec->mutable_script(), msg.es_msg().event.exec.script, msg.script().value());
  }

  if (msg.es_msg().version >= 3 && msg.working_dir().has_value()) {
    EncodeFileInfo(pb_exec->mutable_working_directory(), msg.es_msg().event.exec.cwd,
                   msg.working_dir().value());
  }

  uint32_t arg_count = esapi_->ExecArgCount(&msg.es_msg().event.exec);
  if (arg_count > 0) {
    pb_exec->mutable_args()->Reserve(arg_count);
    for (uint32_t i = 0; i < arg_count; i++) {
      es_string_token_t tok = esapi_->ExecArg(&msg.es_msg().event.exec, i);
      pb_exec->add_args(tok.data, tok.length);
    }
  }

  uint32_t env_count = esapi_->ExecEnvCount(&msg.es_msg().event.exec);
  if (env_count > 0) {
    pb_exec->mutable_envs()->Reserve(env_count);
    for (uint32_t i = 0; i < env_count; i++) {
      es_string_token_t tok = esapi_->ExecEnv(&msg.es_msg().event.exec, i);
      pb_exec->add_envs(tok.data, tok.length);
    }
  }

  if (msg.es_msg().version >= 4) {
    int32_t max_fd = -1;
    uint32_t fd_count = esapi_->ExecFDCount(&msg.es_msg().event.exec);
    if (fd_count > 0) {
      pb_exec->mutable_fds()->Reserve(fd_count);
      for (uint32_t i = 0; i < fd_count; i++) {
        const es_fd_t *fd = esapi_->ExecFD(&msg.es_msg().event.exec, i);
        max_fd = std::max(max_fd, fd->fd);
        ::pbv1::FileDescriptor *pb_fd = pb_exec->add_fds();
        pb_fd->set_fd(fd->fd);
        pb_fd->set_fd_type(GetFileDescriptorType(fd->fdtype));
        if (fd->fdtype == PROX_FDTYPE_PIPE) {
          pb_fd->set_pipe_id(fd->pipe.pipe_id);
        }
      }
    }

    // If the `max_fd` seen is less than `last_fd`, we know that ES truncated
    // the set of returned file descriptors
    pb_exec->set_fd_list_truncated(max_fd < msg.es_msg().event.exec.last_fd);
  }

  pb_exec->set_decision(GetDecisionEnum(cd.decision));
  pb_exec->set_reason(GetReasonEnum(cd.decision));
  pb_exec->set_mode(GetModeEnum(cd.decisionClientMode));

  if (cd.certSHA256 || cd.certCommonName) {
    EncodeCertificateInfo(pb_exec->mutable_certificate_info(), cd.certSHA256, cd.certCommonName);
  }

  EncodeString([pb_exec] { return pb_exec->mutable_explain(); }, cd.decisionExtra);
  EncodeString([pb_exec] { return pb_exec->mutable_quarantine_url(); }, cd.quarantineURL);

  NSString *orig_path = Utilities::OriginalPathForTranslocation(msg.es_msg().event.exec.target);
  EncodeString([pb_exec] { return pb_exec->mutable_original_path(); }, orig_path);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExit &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Exit *pb_exit = santa_msg->mutable_exit();

  EncodeProcessInfoLight(pb_exit->mutable_instigator(), msg.es_msg().version, msg.es_msg().process,
                         msg.instigator());
  EncodeExitStatus(pb_exit, msg.es_msg().event.exit.stat);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedFork &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Fork *pb_fork = santa_msg->mutable_fork();

  EncodeProcessInfoLight(pb_fork->mutable_instigator(), msg.es_msg().version, msg.es_msg().process,
                         msg.instigator());
  EncodeProcessInfoLight(pb_fork->mutable_child(), msg.es_msg().version,
                         msg.es_msg().event.fork.child, msg.child());

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLink &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Link *pb_link = santa_msg->mutable_link();
  EncodeProcessInfoLight(pb_link->mutable_instigator(), msg.es_msg().version, msg.es_msg().process,
                         msg.instigator());
  EncodeFileInfo(pb_link->mutable_source(), msg.es_msg().event.link.source, msg.source());
  EncodePath(pb_link->mutable_target(), msg.es_msg().event.link.target_dir,
             msg.es_msg().event.link.target_filename);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedRename &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Rename *pb_rename = santa_msg->mutable_rename();
  EncodeProcessInfoLight(pb_rename->mutable_instigator(), msg.es_msg().version,
                         msg.es_msg().process, msg.instigator());
  EncodeFileInfo(pb_rename->mutable_source(), msg.es_msg().event.rename.source, msg.source());
  if (msg.es_msg().event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
    EncodePath(pb_rename->mutable_target(), msg.es_msg().event.rename.destination.existing_file);
    pb_rename->set_target_existed(true);
  } else {
    EncodePath(pb_rename->mutable_target(), msg.es_msg().event.rename.destination.new_path.dir,
               msg.es_msg().event.rename.destination.new_path.filename);
    pb_rename->set_target_existed(false);
  }

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedUnlink &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Unlink *pb_unlink = santa_msg->mutable_unlink();
  EncodeProcessInfoLight(pb_unlink->mutable_instigator(), msg.es_msg().version,
                         msg.es_msg().process, msg.instigator());
  EncodeFileInfo(pb_unlink->mutable_target(), msg.es_msg().event.unlink.target, msg.target());

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeFileAccess(const std::string &policy_version,
                                                   const std::string &policy_name,
                                                   const Message &msg,
                                                   const EnrichedProcess &enriched_process,
                                                   const std::string &target,
                                                   FileAccessPolicyDecision decision) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::FileAccess *file_access = santa_msg->mutable_file_access();

  EncodeProcessInfo(file_access->mutable_instigator(), msg->version, msg->process,
                    enriched_process);
  EncodeFileInfoLight(file_access->mutable_target(), target, false);
  EncodeString([file_access] { return file_access->mutable_policy_version(); }, policy_version);
  EncodeString([file_access] { return file_access->mutable_policy_name(); }, policy_name);

  file_access->set_access_type(GetAccessType(msg->event_type));
  file_access->set_policy_decision(GetPolicyDecision(decision));

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeAllowlist(const Message &msg, const std::string_view hash) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  const es_file_t *es_file = Utilities::GetAllowListTargetFile(msg);

  EnrichedFile enriched_file(std::nullopt, std::nullopt, std::nullopt);
  EnrichedProcess enriched_process;

  ::pbv1::Allowlist *pb_allowlist = santa_msg->mutable_allowlist();
  EncodeProcessInfoLight(pb_allowlist->mutable_instigator(), msg->version, msg->process,
                         enriched_process);

  EncodeFileInfo(pb_allowlist->mutable_target(), es_file, enriched_file,
                 [NSString stringWithFormat:@"%s", hash.data()]);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeBundleHashingEvent(SNTStoredEvent *event) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  ::pbv1::Bundle *pb_bundle = santa_msg->mutable_bundle();

  EncodeHash(pb_bundle->mutable_file_hash(), event.fileSHA256);
  EncodeHash(pb_bundle->mutable_bundle_hash(), event.fileBundleHash);
  EncodeString([pb_bundle] { return pb_bundle->mutable_bundle_name(); },
               NonNull(event.fileBundleName));
  EncodeString([pb_bundle] { return pb_bundle->mutable_bundle_id(); }, NonNull(event.fileBundleID));
  EncodeString([pb_bundle] { return pb_bundle->mutable_bundle_path(); },
               NonNull(event.fileBundlePath));
  EncodeString([pb_bundle] { return pb_bundle->mutable_path(); }, NonNull(event.filePath));

  return FinalizeProto(santa_msg);
}

static void EncodeDisk(::pbv1::Disk *pb_disk, ::pbv1::Disk_Action action, NSDictionary *props) {
  pb_disk->set_action(action);

  NSString *dmg_path = nil;
  NSString *serial = nil;
  if ([props[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmg_path = Utilities::DiskImageForDevice(props[@"DADevicePath"]);
  } else {
    serial = Utilities::SerialForDevice(props[@"DADevicePath"]);
  }

  NSString *model = [NSString
    stringWithFormat:@"%@ %@", NonNull(props[@"DADeviceVendor"]), NonNull(props[@"DADeviceModel"])];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  EncodeString([pb_disk] { return pb_disk->mutable_mount(); }, [props[@"DAVolumePath"] path]);
  EncodeString([pb_disk] { return pb_disk->mutable_volume(); }, props[@"DAVolumeName"]);
  EncodeString([pb_disk] { return pb_disk->mutable_bsd_name(); }, props[@"DAMediaBSDName"]);
  EncodeString([pb_disk] { return pb_disk->mutable_fs(); }, props[@"DAVolumeKind"]);
  EncodeString([pb_disk] { return pb_disk->mutable_model(); }, model);
  EncodeString([pb_disk] { return pb_disk->mutable_serial(); }, serial);
  EncodeString([pb_disk] { return pb_disk->mutable_bus(); }, props[@"DADeviceProtocol"]);
  EncodeString([pb_disk] { return pb_disk->mutable_dmg_path(); }, dmg_path);
  EncodeString([pb_disk] { return pb_disk->mutable_mount_from(); },
               MountFromName([props[@"DAVolumePath"] path]));

  if (props[@"DAAppearanceTime"]) {
    // Note: `DAAppearanceTime` is set via `CFAbsoluteTimeGetCurrent`, which uses the defined
    // reference date of `Jan 1 2001 00:00:00 GMT` (not the typical `00:00:00 UTC on 1 January
    // 1970`).
    NSDate *appearance =
      [NSDate dateWithTimeIntervalSinceReferenceDate:[props[@"DAAppearanceTime"] doubleValue]];
    NSTimeInterval interval = [appearance timeIntervalSince1970];
    double seconds;
    double fractional = modf(interval, &seconds);
    struct timespec ts = {
      .tv_sec = (long)seconds,
      .tv_nsec = (long)(fractional * NSEC_PER_SEC),
    };
    EncodeTimestamp(pb_disk->mutable_appearance(), ts);
    Timestamp timestamp = pb_disk->appearance();
  }
}

std::vector<uint8_t> Protobuf::SerializeDiskAppeared(NSDictionary *props) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  EncodeDisk(santa_msg->mutable_disk(), ::pbv1::Disk::ACTION_APPEARED, props);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeDiskDisappeared(NSDictionary *props) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  EncodeDisk(santa_msg->mutable_disk(), ::pbv1::Disk::ACTION_DISAPPEARED, props);

  return FinalizeProto(santa_msg);
}

}  // namespace santa::santad::logs::endpoint_security::serializers
