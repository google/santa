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

#include <bsm/libbsm.h>
#include <libgen.h>
#include <mach/message.h>
#import <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/kauth.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/santad/SNTDecisionCache.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

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

// These functions are exported by the Security framework, but are not included in headers
extern "C" Boolean SecTranslocateIsTranslocatedURL(CFURLRef path, bool* isTranslocated, CFErrorRef* __nullable error);
extern "C" CFURLRef __nullable SecTranslocateCreateOriginalPathForURL(CFURLRef translocatedPath, CFErrorRef* __nullable error);

namespace santa::santad::logs::endpoint_security::serializers {

/*
 * ~~~ BEGIN:
 * TODO: These functions should be moved to some common util file once
 * more enrichers exist...
 */

// TODO(mlw): Return a sanitized string?
static inline std::string_view FilePath(const es_file_t* file) {
  return std::string_view(file->path.data);
}

static inline pid_t Pid(const audit_token_t& tok) {
  return audit_token_to_pid(tok);
}

static inline pid_t Pidversion(const audit_token_t& tok) {
  return audit_token_to_pidversion(tok);
}

static inline pid_t RealUser(const audit_token_t& tok) {
  return audit_token_to_ruid(tok);
}

static inline pid_t RealGroup(const audit_token_t& tok) {
  return audit_token_to_rgid(tok);
}

static inline void SetThreadIDs(uid_t uid, gid_t gid) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated"
  pthread_setugid_np(uid, gid);
#pragma clang diagnostic pop
}

static inline const mach_port_t GetDefaultIOKitCommsPort() {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  return kIOMasterPortDefault;
#pragma clang diagnostic pop
}

static NSString* SerialForDevice(NSString* devPath) {
  if (!devPath.length) {
    return nil;
  }
  NSString *serial;
  io_registry_entry_t device = IORegistryEntryFromPath(GetDefaultIOKitCommsPort(), devPath.UTF8String);
  while (!serial && device) {
    CFMutableDictionaryRef device_properties = NULL;
    IORegistryEntryCreateCFProperties(device, &device_properties, kCFAllocatorDefault, kNilOptions);
    NSDictionary *properties = CFBridgingRelease(device_properties);
    if (properties[@"Serial Number"]) {
      serial = properties[@"Serial Number"];
    } else if (properties[@"kUSBSerialNumberString"]) {
      serial = properties[@"kUSBSerialNumberString"];
    }

    if (serial) {
      IOObjectRelease(device);
      break;
    }

    io_registry_entry_t parent;
    IORegistryEntryGetParentEntry(device, kIOServicePlane, &parent);
    IOObjectRelease(device);
    device = parent;
  }

  return [serial stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

static NSString* DiskImageForDevice(NSString *devPath) {
  devPath = [devPath stringByDeletingLastPathComponent];
  if (!devPath.length) {
    return nil;
  }

  io_registry_entry_t device = IORegistryEntryFromPath(GetDefaultIOKitCommsPort(), devPath.UTF8String);
  CFMutableDictionaryRef device_properties = NULL;
  IORegistryEntryCreateCFProperties(device, &device_properties, kCFAllocatorDefault, kNilOptions);
  NSDictionary *properties = CFBridgingRelease(device_properties);
  IOObjectRelease(device);

  if (properties[@"image-path"]) {
    NSString *result = [[NSString alloc] initWithData:properties[@"image-path"] encoding:NSUTF8StringEncoding];
    return [result stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  } else {
    return nil;
  }
}

static NSString* OriginalPathForTranslocation(const es_process_t* esProc) {
  if (!esProc) {
    return nil;
  }

  CFURLRef cfExecURL = (__bridge CFURLRef)[NSURL fileURLWithPath:@(esProc->executable->path.data)];
  NSURL *origURL = nil;
  bool isTranslocated = false;

  if (SecTranslocateIsTranslocatedURL(cfExecURL, &isTranslocated, NULL)) {
    bool dropPrivs = true;
    if (@available(macOS 12.0, *)) {
      dropPrivs = false;
    }

    if (dropPrivs) {
      SetThreadIDs(RealUser(esProc->audit_token), RealGroup(esProc->audit_token));
    }

    origURL = CFBridgingRelease(SecTranslocateCreateOriginalPathForURL(cfExecURL, NULL));

    if (dropPrivs) {
      SetThreadIDs(KAUTH_UID_NONE, KAUTH_GID_NONE);
    }
  }

  return [origURL path];
}

static NSDateFormatter* GetDateFormatter() {
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

/*
 * TODO: These functions should be moved to some common util file once
 * more enrichers exist...
 * ~~~ END: ^^^^
 */

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
    case SNTEventStateAllowBinary:
      return "BINARY";
    case SNTEventStateAllowCompiler:
      return "COMPILER";
    case SNTEventStateAllowTransitive:
      return "TRANSITIVE";
    case SNTEventStateAllowPendingTransitive:
      return "PENDING_TRANSITIVE";
    case SNTEventStateAllowCertificate:
      return "CERT";
    case SNTEventStateAllowScope:
      return "SCOPE";
    case SNTEventStateAllowTeamID:
      return "TEAMID";
    case SNTEventStateAllowUnknown:
      return "UNKNOWN";
    case SNTEventStateBlockBinary:
      return "BINARY";
    case SNTEventStateBlockCertificate:
      return "CERT";
    case SNTEventStateBlockScope:
      return "SCOPE";
    case SNTEventStateBlockTeamID:
      return "TEAMID";
    case SNTEventStateBlockLongPath:
      return "LONG_PATH";
    case SNTEventStateBlockUnknown:
      return "UNKNOWN";
    default:
      return "NOTRUNNING";
  }
}

std::string GetModeString(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor:
      return "M";
    case SNTClientModeLockdown:
      return "L";
    default:
      return "U";
  }
}

static inline void AppendProcess(std::stringstream& ss,
                                 const es_process_t* es_proc) {
  char bname[MAXPATHLEN];
  ss << "|pid=" << Pid(es_proc->audit_token)
     << "|ppid=" << es_proc->original_ppid
     << "|process=" << basename_r(FilePath(es_proc->executable).data(), bname)
     << "|processpath=" << FilePath(es_proc->executable);
}

static inline void AppendUserGroup(std::stringstream& ss,
                                   const audit_token_t& tok,
                                   std::optional<std::shared_ptr<std::string>> user,
                                   std::optional<std::shared_ptr<std::string>> group) {
  ss << "|uid=" << RealUser(tok)
     << "|user=" << (user.has_value() ? user->get()->c_str() : "(null)")
     << "|gid=" << RealGroup(tok)
     << "|group=" << (group.has_value() ? group->get()->c_str() : "(null)");
}

static char* FormattedDateString(char *buf, size_t len) {
  struct timeval tv;
  struct tm tm;

  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);

  strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(buf, len, "%s.%03dZ", buf, tv.tv_usec / 1000);

  return buf;
}

static inline NSString* NonNull(NSString *str) {
  return str ?: @"";
}

std::shared_ptr<BasicString> BasicString::Create(
    std::shared_ptr<EndpointSecurityAPI> esapi,
    bool prefix_time_name) {
  return std::make_shared<BasicString>(esapi, prefix_time_name);
}

BasicString::BasicString(std::shared_ptr<EndpointSecurityAPI> esapi,
                         bool prefix_time_name)
    : esapi_(esapi), prefix_time_name_(prefix_time_name) {}

std::stringstream BasicString::CreateDefaultStringStream() {
  std::stringstream ss;

  if (prefix_time_name_) {
    char buf[32];

    ss << "[" << FormattedDateString(buf, sizeof(buf)) << "] I santad: ";
    return ss;
  }

  return ss;
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedClose& msg) {
  const es_message_t &esm = *msg.es_msg_;

  auto ss = CreateDefaultStringStream();

  ss << "action=WRITE|path=" << FilePath(esm.event.close.target);

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExchange& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  ss << "action=EXCHANGE|path=" << FilePath(esm.event.exchangedata.file1)
    << "|newpath=" << FilePath(esm.event.exchangedata.file2);

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  SNTCachedDecision *cd = [[SNTDecisionCache sharedCache]
      cachedDecisionForFile:esm.event.exec.target->executable->stat];

  ss << "action=EXEC|decision=" << GetDecisionString(cd.decision)
     << "|reason=" << GetReasonString(cd.decision);

  if (cd.decisionExtra) {
    ss << "|explain=" << [cd.decisionExtra UTF8String];
  }

  if (cd.sha256) {
    ss << "|sha256=" << [cd.sha256 UTF8String];
  }

  if (cd.certSHA256) {
    ss << "|cert_sha256=" << [cd.certSHA256 UTF8String]
       << "|cert_cn=" << [NonNull(sanitizeString(cd.certCommonName)) UTF8String];
  }

  if (cd.teamID.length) {
    ss << "|teamid=" << [NonNull(cd.teamID) UTF8String];
  }

  if (cd.quarantineURL) {
    ss << "|quarantine_url=" << [NonNull(sanitizeString(cd.quarantineURL)) UTF8String];
  }

  ss << "|pid=" << Pid(esm.event.exec.target->audit_token)
     << "|pidversion=" << Pidversion(esm.event.exec.target->audit_token)
     << "|ppid=" << esm.event.exec.target->original_ppid;

  AppendUserGroup(ss,
                  esm.event.exec.target->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  ss << "|mode=" << GetModeString([[SNTConfigurator configurator] clientMode])
     << "|path=" << FilePath(esm.event.exec.target->executable);

  NSString *origPath = OriginalPathForTranslocation(esm.event.exec.target);
  if (origPath) {
    ss << "|origpath=" << origPath;
  }

  uint32_t argCount = esapi_->ExecArgCount(&esm.event.exec);
  if (argCount > 0) {
    ss << "|args=";
    for (uint32_t i = 0; i < argCount; i++) {
      if (i != 0) {
        ss << " ";
      }

      ss << esapi_->ExecArg(&esm.event.exec, i).data;
    }
  }

  if ([[SNTConfigurator configurator] enableMachineIDDecoration]) {
    ss << "|machineid="
       << [NonNull([[SNTConfigurator configurator] machineID]) UTF8String];
  }

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExit& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  ss << "action=EXIT|pid=" << Pid(esm.process->audit_token)
    << "|pidversion=" << Pidversion(esm.process->audit_token)
    << "|ppid=" << esm.process->original_ppid
    << "|uid=" << RealUser(esm.process->audit_token)
    << "|gid=" << RealGroup(esm.process->audit_token);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedFork& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  ss << "action=FORK|pid=" << Pid(esm.event.fork.child->audit_token)
    << "|pidversion=" << Pidversion(esm.event.fork.child->audit_token)
    << "|ppid=" << esm.event.fork.child->original_ppid
    << "|uid=" << RealUser(esm.event.fork.child->audit_token)
    << "|gid=" << RealGroup(esm.event.fork.child->audit_token);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLink& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  ss << "action=LINK|path=" << FilePath(esm.event.link.source)
    << "|newpath=" << FilePath(esm.event.link.target_dir)
    << "/" << esm.event.link.target_filename.data;

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedRename& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  ss << "action=RENAME|path=" << FilePath(esm.event.rename.source)
     << "|newpath=";

  switch (esm.event.rename.destination_type) {
    case ES_DESTINATION_TYPE_EXISTING_FILE:
      ss << FilePath(esm.event.rename.destination.existing_file);
      break;
    case ES_DESTINATION_TYPE_NEW_PATH:
      ss << FilePath(esm.event.rename.destination.new_path.dir)
         << "/" << esm.event.rename.destination.new_path.filename.data;
      break;
    default:
      ss << "(null)";
      break;
  }

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedUnlink& msg) {
  const es_message_t &esm = *msg.es_msg_;
  auto ss = CreateDefaultStringStream();

  ss << "action=DELETE|path=" << FilePath(esm.event.unlink.target);

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeAllowlist(const Message& msg,
                                                     const std::string_view hash) {
  auto ss = CreateDefaultStringStream();

  ss << "action=ALLOWLIST|pid=" << Pid(msg->process->audit_token)
     << "|pidversion=" << Pidversion(msg->process->audit_token)
     << "|path=" << FilePath(GetAllowListTargetFile(msg))
     << "|sha256=" << hash;

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeBundleHashingEvent(SNTStoredEvent* event) {
  auto ss = CreateDefaultStringStream();

  ss << "action=BUNDLE|sha256=" << [NonNull(event.fileSHA256) UTF8String]
     << "|bundlehash=" << [NonNull(event.fileBundleHash) UTF8String]
     << "|bundlename=" << [NonNull(event.fileBundleName) UTF8String]
     << "|bundleid=" << [NonNull(event.fileBundleID) UTF8String]
     << "|bundlepath=" << [NonNull(event.fileBundlePath) UTF8String]
     << "|path=" << [NonNull(event.filePath) UTF8String];

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeDiskAppeared(NSDictionary* props) {
  NSString *dmgPath = nil;
  NSString *serial = nil;
  if ([props[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmgPath = DiskImageForDevice(props[@"DADevicePath"]);
  } else {
    serial = SerialForDevice(props[@"DADevicePath"]);
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@",
                        NonNull(props[@"DADeviceVendor"]),
                        NonNull(props[@"DADeviceModel"])];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  NSString *appearanceDateString =
    [GetDateFormatter()
        stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:
            [props[@"DAAppearanceTime"] doubleValue]]];

  auto ss = CreateDefaultStringStream();
  ss << "action=DISKAPPEAR"
     << "|mount=" << [NonNull([props[@"DAVolumePath"] path]) UTF8String]
     << "|volume=" << [NonNull(props[@"DAVolumeName"]) UTF8String]
     << "|bsdname=" << [NonNull(props[@"DAMediaBSDName"]) UTF8String]
     << "|fs=" << [NonNull(props[@"DAVolumeKind"]) UTF8String]
     << "|model=" << [NonNull(model) UTF8String]
     << "|serial=" << [NonNull(serial) UTF8String]
     << "|bus=" << [NonNull(props[@"DADeviceProtocol"]) UTF8String]
     << "|dmgpath=" << [NonNull(dmgPath) UTF8String]
     << "|appearance=" << [NonNull(appearanceDateString) UTF8String];

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeDiskDisappeared(NSDictionary* props) {
  auto ss = CreateDefaultStringStream();

  ss << "action=DISKDISAPPEAR"
     << "|mount=" << [NonNull([props[@"DAVolumePath"] path]) UTF8String]
     << "|volume=" << [NonNull(props[@"DAVolumeName"]) UTF8String]
     << "|bsdname=" << [NonNull(props[@"DAMediaBSDName"]) UTF8String];

  std::string s = ss.str();

  return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace santa::santad::logs::endpoint_security::serializers
