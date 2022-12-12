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
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedLink;
using santa::santad::event_providers::endpoint_security::EnrichedRename;
using santa::santad::event_providers::endpoint_security::EnrichedUnlink;
using santa::santad::event_providers::endpoint_security::Message;
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
    case SNTEventStateAllowUnknown: return "UNKNOWN";
    case SNTEventStateBlockBinary: return "BINARY";
    case SNTEventStateBlockCertificate: return "CERT";
    case SNTEventStateBlockScope: return "SCOPE";
    case SNTEventStateBlockTeamID: return "TEAMID";
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
                                                 bool prefix_time_name) {
  return std::make_shared<BasicString>(esapi, prefix_time_name);
}

BasicString::BasicString(std::shared_ptr<EndpointSecurityAPI> esapi, bool prefix_time_name)
    : esapi_(esapi), prefix_time_name_(prefix_time_name) {}

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

  AppendProcess(str, esm.process);
  AppendUserGroup(str, esm.process->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExchange &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=EXCHANGE|path=");
  str.append(FilePath(esm.event.exchangedata.file1).Sanitized());
  str.append("|newpath=");
  str.append(FilePath(esm.event.exchangedata.file2).Sanitized());

  AppendProcess(str, esm.process);
  AppendUserGroup(str, esm.process->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString(1024);  // EXECs tend to be bigger, reserve more space.

  SNTCachedDecision *cd =
    [[SNTDecisionCache sharedCache] cachedDecisionForFile:esm.event.exec.target->executable->stat];

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
  str.append(GetModeString([[SNTConfigurator configurator] clientMode]));
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

  AppendProcess(str, esm.process);
  AppendUserGroup(str, esm.process->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

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

  AppendProcess(str, esm.process);
  AppendUserGroup(str, esm.process->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedUnlink &msg) {
  const es_message_t &esm = msg.es_msg();
  std::string str = CreateDefaultString();

  str.append("action=DELETE|path=");
  str.append(FilePath(esm.event.unlink.target).Sanitized());

  AppendProcess(str, esm.process);
  AppendUserGroup(str, esm.process->audit_token, msg.instigator().real_user(),
                  msg.instigator().real_group());

  return FinalizeString(str);
}

std::vector<uint8_t> BasicString::SerializeFileAccess(
  const std::string &policy_version, const std::string &policy_name,
  const santa::santad::event_providers::endpoint_security::Message &msg,
  const santa::santad::event_providers::endpoint_security::EnrichedProcess &enriched_process,
  const std::string &target, FileAccessPolicyDecision decision) {
  return {};
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
