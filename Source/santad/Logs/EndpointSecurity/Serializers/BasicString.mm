/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"

#import <Security/Security.h>
#include <bsm/libbsm.h>
#include <libgen.h>
#include <mach/message.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/kauth.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <string>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedCSInvalidated;
using santa::santad::event_providers::endpoint_security::EnrichedEventType;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedLink;
using santa::santad::event_providers::endpoint_security::EnrichedLoginLogin;
using santa::santad::event_providers::endpoint_security::EnrichedLoginLogout;
using santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLock;
using santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLogin;
using santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionLogout;
using santa::santad::event_providers::endpoint_security::EnrichedLoginWindowSessionUnlock;
using santa::santad::event_providers::endpoint_security::EnrichedOpenSSHLogin;
using santa::santad::event_providers::endpoint_security::EnrichedOpenSSHLogout;
using santa::santad::event_providers::endpoint_security::EnrichedProcess;
using santa::santad::event_providers::endpoint_security::EnrichedRename;
using santa::santad::event_providers::endpoint_security::EnrichedScreenSharingAttach;
using santa::santad::event_providers::endpoint_security::EnrichedScreenSharingDetach;
using santa::santad::event_providers::endpoint_security::EnrichedUnlink;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::serializers::Utilities::MountFromName;
using santa::santad::logs::endpoint_security::serializers::Utilities::NonNull;
using santa::santad::logs::endpoint_security::serializers::Utilities::Pid;
using santa::santad::logs::endpoint_security::serializers::Utilities::Pidversion;
using santa::santad::logs::endpoint_security::serializers::Utilities::RealGroup;
using santa::santad::logs::endpoint_security::serializers::Utilities::RealUser;

namespace santa::santad::logs::endpoint_security::serializers {

static inline SanitizableString FilePath(const es_file_t *file) {
  return SanitizableString(file);
}

static NSDateFormatter *GetDateFormatter() {
  static dispatch_once_t onceToken;
  static NSDateFormatter *dateFormatter;

  dispatch_once(&onceToken, ^{
    dateFormatter = [[NSDateFormatter alloc] init];
    dateFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    dateFormatter.calendar = [NSCalendar calendarWithIdentifier:NSCalendarIdentifierISO8601];
    dateFormatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
  });

  return dateFormatter;
}

std::string GetDecisionString(SNTEventState event_state) {
  if (event_state & SNTEventStateAllow) {
    return "ALLOW";
  } else if (event_state & SNTEventStateBlock) {
    return "DENY";
  } else {
    return "UNKNOWN";
  }
}

std::string GetReasonString(SNTEventState event_state) {
  switch (event_state) {
    case SNTEventStateAllowBinary: return "BINARY";
    case SNTEventStateAllowCompiler: return "COMPILER";
    case SNTEventStateAllowTransitive: return "TRANSITIVE";
    case SNTEventStateAllowPendingTransitive: return "PENDING_TRANSITIVE";
    case SNTEventStateAllowCertificate: return "CERT";
    case SNTEventStateAllowScope: return "SCOPE";
    case SNTEventStateAllowTeamID: return "TEAMID";
    case SNTEventStateAllowSigningID: return "SIGNINGID";
    case SNTEventStateAllowCDHash: return "CDHASH";
    case SNTEventStateAllowUnknown: return "UNKNOWN";
    case SNTEventStateBlockBinary: return "BINARY";
    case SNTEventStateBlockCertificate: return "CERT";
    case SNTEventStateBlockScope: return "SCOPE";
    case SNTEventStateBlockTeamID: return "TEAMID";
    case SNTEventStateBlockSigningID: return "SIGNINGID";
    case SNTEventStateBlockCDHash: return "CDHASH";
    case SNTEventStateBlockLongPath: return "LONG_PATH";
    case SNTEventStateBlockUnknown: return "UNKNOWN";
    default: return "NOTRUNNING";
  }
}

std::string GetModeString(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor: return "M";
    case SNTClientModeLockdown: return "L";
    default: return "U";
  }
}

std::string GetAccessTypeString(es_event_type_t event_type) {
  switch (event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE: return "CLONE";
    case ES_EVENT_TYPE_AUTH_COPYFILE: return "COPYFILE";
    case ES_EVENT_TYPE_AUTH_CREATE: return "CREATE";
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA: return "EXCHANGEDATA";
    case ES_EVENT_TYPE_AUTH_LINK: return "LINK";
    case ES_EVENT_TYPE_AUTH_OPEN: return "OPEN";
    case ES_EVENT_TYPE_AUTH_RENAME: return "RENAME";
    case ES_EVENT_TYPE_AUTH_TRUNCATE: return "TRUNCATE";
    case ES_EVENT_TYPE_AUTH_UNLINK: return "UNLINK";
    default: return "UNKNOWN_TYPE_" + std::to_string(event_type);
  }
}

std::string GetFileAccessPolicyDecisionString(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kNoPolicy: return "NO_POLICY";
    case FileAccessPolicyDecision::kDenied: return "DENIED";
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return "DENIED_INVALID_SIGNATURE";
    case FileAccessPolicyDecision::kAllowed: return "ALLOWED";
    case FileAccessPolicyDecision::kAllowedReadAccess: return "ALLOWED_READ_ACCESS";
    case FileAccessPolicyDecision::kAllowedAuditOnly: return "AUDIT_ONLY";
    default: return "UNKNOWN_DECISION_" + std::to_string((int)decision);
  }
}

static inline void AppendProcess(std::string &str, const es_process_t *es_proc) {
  char bname[MAXPATHLEN];
  str.append("|pid=");
  str.append(std::to_string(Pid(es_proc->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(es_proc->original_ppid));
  str.append("|process=");
  str.append(basename_r(FilePath(es_proc->executable).Sanitized().data(), bname) ?: "");
  str.append("|processpath=");
  str.append(FilePath(es_proc->executable).Sanitized());
}

static inline void AppendUserGroup(std::string &str, const audit_token_t &tok,
                                   const std::optional<std::shared_ptr<std::string>> &user,
                                   const std::optional<std::shared_ptr<std::string>> &group) {
  str.append("|uid=");
  str.append(std::to_string(RealUser(tok)));
  str.append("|user=");
  str.append(user.has_value() ? user->get()->c_str() : "(null)");
  str.append("|gid=");
  str.append(std::to_string(RealGroup(tok)));
  str.append("|group=");
  str.append(group.has_value() ? group->get()->c_str() : "(null)");
}

static inline void AppendInstigator(std::string &str, const EnrichedEventType &event) {
  AppendProcess(str, event->process);
  AppendUserGroup(str, event->process->audit_token, event.instigator().real_user(),
                  event.instigator().real_group());
}

#if HAVE_MACOS_13

static inline void AppendEventUser(std::string &str, const es_string_token_t &user,
                                   std::optional<uid_t> uid) {
  if (user.length > 0) {
    str.append("|event_user=");
    str.append(user.data);
  }

  if (uid.has_value()) {
    str.append("|event_uid=");
    str.append(std::to_string(uid.value()));
  }
}

static inline void AppendGraphicalSession(std::string &str, es_graphical_session_id_t session_id) {
  str.append("|graphical_session_id=");
  str.append(std::to_string(session_id));
}

static inline void AppendSocketAddress(std::string &str, es_address_type_t type,
                                       es_string_token_t addr) {
  str.append("|address_type=");
  switch (type) {
    case ES_ADDRESS_TYPE_NONE: str.append("none"); break;
    case ES_ADDRESS_TYPE_IPV4: str.append("ipv4"); break;
    case ES_ADDRESS_TYPE_IPV6: str.append("ipv6"); break;
    case ES_ADDRESS_TYPE_NAMED_SOCKET: str.append("named_socket"); break;
    default: str.append("unknown"); break;
  }

  if (addr.length > 0) {
    str.append("|address=");
    str.append(SanitizableString(addr).Sanitized());
  }
}

static inline std::string GetOpenSSHLoginResult(std::string &str,
                                                es_openssh_login_result_type_t result) {
  switch (result) {
    case ES_OPENSSH_LOGIN_EXCEED_MAXTRIES: return "LOGIN_EXCEED_MAXTRIES";
    case ES_OPENSSH_LOGIN_ROOT_DENIED: return "LOGIN_ROOT_DENIED";
    case ES_OPENSSH_AUTH_SUCCESS: return "AUTH_SUCCESS";
    case ES_OPENSSH_AUTH_FAIL_NONE: return "AUTH_FAIL_NONE";
    case ES_OPENSSH_AUTH_FAIL_PASSWD: return "AUTH_FAIL_PASSWD";
    case ES_OPENSSH_AUTH_FAIL_KBDINT: return "AUTH_FAIL_KBDINT";
    case ES_OPENSSH_AUTH_FAIL_PUBKEY: return "AUTH_FAIL_PUBKEY";
    case ES_OPENSSH_AUTH_FAIL_HOSTBASED: return "AUTH_FAIL_HOSTBASED";
    case ES_OPENSSH_AUTH_FAIL_GSSAPI: return "AUTH_FAIL_GSSAPI";
    case ES_OPENSSH_INVALID_USER: return "INVALID_USER";
    default: return "UNKNOWN";
  }
}

#endif

static char *FormattedDateString(char *buf, size_t len) {
  struct timeval tv;
  struct tm tm;

  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);

  strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(buf, len, "%s.%03dZ", buf, tv.tv_usec / 1000);

  return buf;
}

std::shared_ptr<BasicString> BasicString::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                                 SNTDecisionCache *decision_cache,
                                                 bool prefix_time_name) {
  return std::make_shared<BasicString>(esapi, decision_cache, prefix_time_name);
}

BasicString::BasicString(std::shared_ptr<EndpointSecurityAPI> esapi,
                         SNTDecisionCache *decision_cache, bool prefix_time_name)
    : Serializer(std::move(decision_cache)), esapi_(esapi), prefix_time_name_(prefix_time_name) {}

std::string BasicString::CreateDefaultString(size_t reserved_size) {
  std::string str;
  str.reserve(1024);

  if (prefix_time_name_) {
    char buf[32];

    str.append("[");
    str.append(FormattedDateString(buf, sizeof(buf)));
    str.append("] I santad: ");
  }

  return str;
}

std::vector<uint8_t> BasicString::FinalizeString(std::string &str) {
  if (EnabledMachineID()) {
    str.append("|machineid=");
    str.append(MachineID());
  }
  str.append("\n");

  std::vector<uint8_t> vec(str.length());
  std::copy(str.begin(), str.end(), vec.begin());
  return vec;
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedClose &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=WRITE|path=");
  str.append(FilePath(esm.event.close.target).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExchange &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=EXCHANGE|path=");
  str.append(FilePath(esm.event.exchangedata.file1).Sanitized());
  str.append("|newpath=");
  str.append(FilePath(esm.event.exchangedata.file2).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec &msg, SNTCachedDecision *cd) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString(1024);  // EXECs tend to be bigger, reserve more space.

  str.append("action=EXEC|decision=");
  str.append(GetDecisionString(cd.decision));
  str.append("|reason=");
  str.append(GetReasonString(cd.decision));

  if (cd.decisionExtra) {
    str.append("|explain=");
    str.append([cd.decisionExtra UTF8String]);
  }

  if (cd.sha256) {
    str.append("|sha256=");
    str.append([cd.sha256 UTF8String]);
  }

  if (cd.certSHA256) {
    str.append("|cert_sha256=");
    str.append([cd.certSHA256 UTF8String]);
    str.append("|cert_cn=");
    str.append(SanitizableString(cd.certCommonName).Sanitized());
  }

  if (cd.teamID.length) {
    str.append("|teamid=");
    str.append([NonNull(cd.teamID) UTF8String]);
  }

  if (cd.quarantineURL) {
    str.append("|quarantine_url=");
    str.append(SanitizableString(cd.quarantineURL).Sanitized());
  }

  str.append("|pid=");
  str.append(std::to_string(Pid(esm.event.exec.target->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(esm.event.exec.target->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(esm.event.exec.target->original_ppid));

  AppendUserGroup(str, esm.event.exec.target->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

  str.append("|mode=");
  str.append(GetModeString(cd.decisionClientMode));
  str.append("|path=");
  str.append(FilePath(esm.event.exec.target->executable).Sanitized());

  NSString *origPath = Utilities::OriginalPathForTranslocation(esm.event.exec.target);
  if (origPath) {
    str.append("|origpath=");
    str.append(SanitizableString(origPath).Sanitized());
  }

  uint32_t argCount = esapi_->ExecArgCount(&esm.event.exec);
  if (argCount > 0) {
    str.append("|args=");
    for (uint32_t i = 0; i < argCount; i++) {
      if (i != 0) {
        str.append(" ");
      }

      str.append(SanitizableString(esapi_->ExecArg(&esm.event.exec, i)).Sanitized());
    }
  }

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExit &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=EXIT|pid=");
  str.append(std::to_string(Pid(esm.process->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(esm.process->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(esm.process->original_ppid));
  str.append("|uid=");
  str.append(std::to_string(RealUser(esm.process->audit_token)));
  str.append("|gid=");
  str.append(std::to_string(RealGroup(esm.process->audit_token)));

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedFork &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=FORK|pid=");
  str.append(std::to_string(Pid(esm.event.fork.child->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(esm.event.fork.child->audit_token)));
  str.append("|ppid=");
  str.append(std::to_string(esm.event.fork.child->original_ppid));
  str.append("|uid=");
  str.append(std::to_string(RealUser(esm.event.fork.child->audit_token)));
  str.append("|gid=");
  str.append(std::to_string(RealGroup(esm.event.fork.child->audit_token)));

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLink &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=LINK|path=");
  str.append(FilePath(esm.event.link.source).Sanitized());
  str.append("|newpath=");
  str.append(FilePath(esm.event.link.target_dir).Sanitized());
  str.append("/");
  str.append(SanitizableString(esm.event.link.target_filename).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedRename &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=RENAME|path=");
  str.append(FilePath(esm.event.rename.source).Sanitized());
  str.append("|newpath=");

  switch (esm.event.rename.destination_type) {
    case ES_DESTINATION_TYPE_EXISTING_FILE:
      str.append(FilePath(esm.event.rename.destination.existing_file).Sanitized());
      break;
    case ES_DESTINATION_TYPE_NEW_PATH:
      str.append(FilePath(esm.event.rename.destination.new_path.dir).Sanitized());
      str.append("/");
      str.append(SanitizableString(esm.event.rename.destination.new_path.filename).Sanitized());
      break;
    default: str.append("(null)"); break;
  }

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedUnlink &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=DELETE|path=");
  str.append(FilePath(esm.event.unlink.target).Sanitized());

  AppendInstigator(str, msg);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedCSInvalidated &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=CODESIGNING_INVALIDATED");
  AppendInstigator(str, msg);
  str.append("|codesigning_flags=");
  str.append([NSString stringWithFormat:@"0x%08x", esm.process->codesigning_flags].UTF8String);
  return FinalizeString(str);
}

#if HAVE_MACOS_13
std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionLogin &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_LOGIN");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_login->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_login->graphical_session_id);

  return FinalizeString(str);
};

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionLogout &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_LOGOUT");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_logout->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_logout->graphical_session_id);

  return FinalizeString(str);
};

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionLock &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_LOCK");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_lock->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_lock->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginWindowSessionUnlock &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN_WINDOW_SESSION_UNLOCK");
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.lw_session_unlock->username, msg.UID());
  AppendGraphicalSession(str, msg->event.lw_session_unlock->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedScreenSharingAttach &msg) {
  std::string str = CreateDefaultString();

  str.append("action=SCREEN_SHARING_ATTACH|success=");
  str.append(msg->event.screensharing_attach->success ? "true" : "false");

  AppendSocketAddress(str, msg->event.screensharing_attach->source_address_type,
                      msg->event.screensharing_attach->source_address);

  if (msg->event.screensharing_attach->viewer_appleid.length > 0) {
    str.append("|viewer=");
    str.append(SanitizableString(msg->event.screensharing_attach->viewer_appleid).Sanitized());
  }

  if (msg->event.screensharing_attach->authentication_type.length > 0) {
    str.append("|auth_type=");
    str.append(SanitizableString(msg->event.screensharing_attach->authentication_type).Sanitized());
  }

  if (msg->event.screensharing_attach->authentication_username.length > 0) {
    str.append("|auth_user=");
    str.append(
      SanitizableString(msg->event.screensharing_attach->authentication_username).Sanitized());
  }

  if (msg->event.screensharing_attach->session_username.length > 0) {
    str.append("|session_user=");
    str.append(SanitizableString(msg->event.screensharing_attach->session_username).Sanitized());
  }

  str.append("|existing_session=");
  str.append(msg->event.screensharing_attach->existing_session ? "true" : "false");

  AppendInstigator(str, msg);
  AppendGraphicalSession(str, msg->event.screensharing_attach->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedScreenSharingDetach &msg) {
  std::string str = CreateDefaultString();

  str.append("action=SCREEN_SHARING_DETACH");

  AppendSocketAddress(str, msg->event.screensharing_detach->source_address_type,
                      msg->event.screensharing_detach->source_address);

  if (msg->event.screensharing_detach->viewer_appleid.length > 0) {
    str.append("|viewer=");
    str.append(SanitizableString(msg->event.screensharing_detach->viewer_appleid).Sanitized());
  }

  AppendInstigator(str, msg);
  AppendGraphicalSession(str, msg->event.screensharing_detach->graphical_session_id);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedOpenSSHLogin &msg) {
  std::string str = CreateDefaultString();

  str.append("action=OPENSSH_LOGIN|success=");
  str.append(msg->event.openssh_login->success ? "true" : "false");
  str.append("|result_type=");
  str.append(GetOpenSSHLoginResult(str, msg->event.openssh_login->result_type));

  AppendSocketAddress(str, msg->event.openssh_login->source_address_type,
                      msg->event.openssh_login->source_address);
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.openssh_login->username,
                  msg->event.openssh_login->has_uid
                    ? std::make_optional<uid_t>(msg->event.openssh_login->uid.uid)
                    : std::nullopt);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedOpenSSHLogout &msg) {
  std::string str = CreateDefaultString();

  str.append("action=OPENSSH_LOGOUT");

  AppendSocketAddress(str, msg->event.openssh_logout->source_address_type,
                      msg->event.openssh_logout->source_address);
  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.openssh_logout->username,
                  std::make_optional<uid_t>(msg->event.openssh_logout->uid));

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginLogin &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGIN|success=");
  str.append(msg->event.login_login->success ? "true" : "false");
  if (!msg->event.login_login->success) {
    str.append("|failure=");
    str.append(SanitizableString(msg->event.login_login->failure_message).Sanitized());
  }

  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.login_login->username,
                  msg->event.login_login->has_uid
                    ? std::make_optional<uid_t>(msg->event.login_login->uid.uid)
                    : std::nullopt);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLoginLogout &msg) {
  std::string str = CreateDefaultString();

  str.append("action=LOGOUT");

  AppendInstigator(str, msg);
  AppendEventUser(str, msg->event.login_logout->username,
                  std::make_optional<uid_t>(msg->event.login_logout->uid));

  return FinalizeString(str);
}
#endif

std::vector<uint8_t> BasicString::SerializeFileAccess(const std::string &policy_version,
                                                      const std::string &policy_name,
                                                      const Message &msg,
                                                      const EnrichedProcess &enriched_process,
                                                      const std::string &target,
                                                      FileAccessPolicyDecision decision) {
  std::string str = CreateDefaultString();

  str.append("action=FILE_ACCESS|policy_version=");
  str.append(policy_version);
  str.append("|policy_name=");
  str.append(policy_name);
  str.append("|path=");
  str.append(target);
  str.append("|access_type=");
  str.append(GetAccessTypeString(msg->event_type));
  str.append("|decision=");
  str.append(GetFileAccessPolicyDecisionString(decision));

  AppendProcess(str, msg->process);
  AppendUserGroup(str, msg->process->audit_token, enriched_process.real_user(),
                  enriched_process.real_group());

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeAllowlist(const Message &msg,
                                                     const std::string_view hash) {
  std::string str = CreateDefaultString();

  str.append("action=ALLOWLIST|pid=");
  str.append(std::to_string(Pid(msg->process->audit_token)));
  str.append("|pidversion=");
  str.append(std::to_string(Pidversion(msg->process->audit_token)));
  str.append("|path=");
  str.append(FilePath(Utilities::GetAllowListTargetFile(msg)).Sanitized());
  str.append("|sha256=");
  str.append(hash);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeBundleHashingEvent(SNTStoredEvent *event) {
  std::string str = CreateDefaultString();

  str.append("action=BUNDLE|sha256=");
  str.append([NonNull(event.fileSHA256) UTF8String]);
  str.append("|bundlehash=");
  str.append([NonNull(event.fileBundleHash) UTF8String]);
  str.append("|bundlename=");
  str.append([NonNull(event.fileBundleName) UTF8String]);
  str.append("|bundleid=");
  str.append([NonNull(event.fileBundleID) UTF8String]);
  str.append("|bundlepath=");
  str.append([NonNull(event.fileBundlePath) UTF8String]);
  str.append("|path=");
  str.append([NonNull(event.filePath) UTF8String]);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeDiskAppeared(NSDictionary *props) {
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

  NSString *appearanceDateString = [GetDateFormatter()
    stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:[props[@"DAAppearanceTime"]
                                                                    doubleValue]]];

  std::string str = CreateDefaultString();
  str.append("action=DISKAPPEAR");
  str.append("|mount=");
  str.append([NonNull([props[@"DAVolumePath"] path]) UTF8String]);
  str.append("|volume=");
  str.append([NonNull(props[@"DAVolumeName"]) UTF8String]);
  str.append("|bsdname=");
  str.append([NonNull(props[@"DAMediaBSDName"]) UTF8String]);
  str.append("|fs=");
  str.append([NonNull(props[@"DAVolumeKind"]) UTF8String]);
  str.append("|model=");
  str.append([NonNull(model) UTF8String]);
  str.append("|serial=");
  str.append([NonNull(serial) UTF8String]);
  str.append("|bus=");
  str.append([NonNull(props[@"DADeviceProtocol"]) UTF8String]);
  str.append("|dmgpath=");
  str.append([NonNull(dmg_path) UTF8String]);
  str.append("|appearance=");
  str.append([NonNull(appearanceDateString) UTF8String]);
  str.append("|mountfrom=");
  str.append([NonNull(MountFromName([props[@"DAVolumePath"] path])) UTF8String]);

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeDiskDisappeared(NSDictionary *props) {
  std::string str = CreateDefaultString();

  str.append("action=DISKDISAPPEAR");
  str.append("|mount=");
  str.append([NonNull([props[@"DAVolumePath"] path]) UTF8String]);
  str.append("|volume=");
  str.append([NonNull(props[@"DAVolumeName"]) UTF8String]);
  str.append("|bsdname=");
  str.append([NonNull(props[@"DAMediaBSDName"]) UTF8String]);

  return FinalizeString(str);
}

}  // namespace santa::santad::logs::endpoint_security::serializers
