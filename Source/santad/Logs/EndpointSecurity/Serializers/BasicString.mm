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

#include <sstream>

#include <bsm/libbsm.h>
#include <libgen.h>
#include <mach/message.h>
#include <sys/param.h>

#import <Security/Security.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/santad/SNTDecisionCache.h"

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

static NSString* OriginalPathForTranslocation(const char *path) {
  if (!path) {
    return nil;
  }

  CFURLRef cfExecURL = (__bridge CFURLRef)[NSURL fileURLWithPath:@(path)];
  NSURL *origURL = nil;
  bool isTranslocated = false;

  if (SecTranslocateIsTranslocatedURL(cfExecURL, &isTranslocated, NULL)) {
    origURL = CFBridgingRelease(SecTranslocateCreateOriginalPathForURL(cfExecURL, NULL));
  }

  return [origURL path];
}


/**
  Sanitize the given C-string, replacing |, \n and \r characters.

  @return a new NSString with the replaced contents, if necessary, otherwise nil.
*/
static NSString* sanitizeCString(const char *str, NSUInteger length) {
  NSUInteger bufOffset = 0, strOffset = 0;
  char c = 0;
  char *buf = NULL;
  BOOL shouldFree = NO;

  if (length < 1) return @"";

  // Loop through the string one character at a time, looking for the characters
  // we want to remove.
  for (const char *p = str; (c = *p) != 0; ++p) {
    if (c == '|' || c == '\n' || c == '\r') {
      if (!buf) {
        // If string size * 6 is more than 64KiB use malloc, otherwise use stack space.
        if (length * 6 > 64 * 1024) {
          buf = (char*)malloc(length * 6);
          shouldFree = YES;
        } else {
          buf = (char*)alloca(length * 6);
        }
      }

      // Copy from the last offset up to the character we just found into the buffer
      ptrdiff_t diff = p - str;
      memcpy(buf + bufOffset, str + strOffset, diff - strOffset);

      // Update the buffer and string offsets
      bufOffset += diff - strOffset;
      strOffset = diff + 1;

      // Replace the found character and advance the buffer offset
      switch (c) {
        case '|':
          memcpy(buf + bufOffset, "<pipe>", 6);
          bufOffset += 6;
          break;
        case '\n':
          memcpy(buf + bufOffset, "\\n", 2);
          bufOffset += 2;
          break;
        case '\r':
          memcpy(buf + bufOffset, "\\r", 2);
          bufOffset += 2;
          break;
      }
    }
  }

  if (strOffset > 0 && strOffset < length) {
    // Copy any characters from the last match to the end of the string into the buffer.
    memcpy(buf + bufOffset, str + strOffset, length - strOffset);
    bufOffset += length - strOffset;
  }

  if (buf) {
    // Only return a new string if there were matches
    NSString *ret = [[NSString alloc] initWithBytes:buf
                                             length:bufOffset
                                           encoding:NSUTF8StringEncoding];
    if (shouldFree) {
      free(buf);
    }

    return ret;
  }
  return nil;
}

/**
  Sanitizes a given string if necessary, otherwise returns the original.
*/
static NSString* sanitizeString(NSString *inStr) {
  NSUInteger length = [inStr lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  if (length < 1) return inStr;

  NSString *ret = sanitizeCString([inStr UTF8String], length);
  if (ret) {
    return ret;
  }
  return inStr;
}

static inline std::string GetDecisionString(SNTEventState event_state) {
  if (event_state & SNTEventStateAllow) {
    return "ALLOW";
  } else if (event_state & SNTEventStateBlock) {
    return "DENY";
  } else {
    return "UNKNOWN";
  }
}

static inline std::string GetReasonString(SNTEventState event_state) {
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
    case SNTEventStateBlockUnknown:
      return "UNKNOWN";
    default:
      return "NOTRUNNING";
  }
}

static inline std::string GetModeString() {
  switch ([[SNTConfigurator configurator] clientMode]) {
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

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedClose &msg) {
  const es_message_t &esm = *msg.es_msg_;

  std::stringstream ss;

  ss << "action=WRITE|path=" << FilePath(esm.event.close.target);

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  LOGE(@"Enriched write: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExchange &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

  ss << "action=EXCHANGE|path=" << FilePath(esm.event.exchangedata.file1)
    << "|newpath=" << FilePath(esm.event.exchangedata.file2);

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  LOGE(@"Enriched exchange: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

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
    ss << "|cert_sha256=" << cd.certSHA256
       << "|cert_cn=" << [sanitizeString(cd.certCommonName) UTF8String];
  }

  if (cd.quarantineURL) {
    ss << "|quarantine_url=" << [sanitizeString(cd.quarantineURL) UTF8String];
  }

  ss << "|pid=" << Pid(esm.event.exec.target->audit_token)
     << "|pidversion=" << Pidversion(esm.event.exec.target->audit_token)
     << "|ppid=" << esm.event.exec.target->original_ppid;

  AppendUserGroup(ss,
                  esm.event.exec.target->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  ss << "|mode=" << GetModeString()
     << "|path=" << FilePath(esm.event.exec.target->executable);

  NSString *origPath = OriginalPathForTranslocation(
      FilePath(esm.event.exec.target->executable).data());
  if (origPath) {
    ss << "|origpath=" << origPath;
  }

  uint32_t argCount = es_exec_arg_count(&(esm.event.exec));
  if (argCount > 0) {
    ss << "|args=";
    for (uint32_t i = 0; i < argCount; i++) {
      if (i != 0) {
        ss << " ";
      }

      ss << es_exec_arg(&esm.event.exec, i).data;
    }
  }

  if ([[SNTConfigurator configurator] enableMachineIDDecoration]) {
    ss << "|machineid="
       << [[[SNTConfigurator configurator] machineID] UTF8String];
  }

  std::string s = ss.str();

  LOGE(@"Enriched exec: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExit &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

  ss << "action=EXIT|pid=" << Pid(esm.process->audit_token)
    << "|pidversion=" << Pidversion(esm.process->audit_token)
    << "|ppid=" << esm.process->original_ppid
    << "|uid=" << RealUser(esm.process->audit_token)
    << "|gid=" << RealGroup(esm.process->audit_token);

  std::string s = ss.str();

  LOGE(@"Enriched exit: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedFork &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

  ss << "action=FORK|pid=" << Pid(esm.event.fork.child->audit_token)
    << "|pidversion=" << Pidversion(esm.event.fork.child->audit_token)
    << "|ppid=" << esm.event.fork.child->original_ppid
    << "|uid=" << RealUser(esm.event.fork.child->audit_token)
    << "|gid=" << RealGroup(esm.event.fork.child->audit_token);

  std::string s = ss.str();

  LOGE(@"Enriched fork: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedLink &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

  ss << "action=LINK|path=" << FilePath(esm.event.link.source)
    << "|newpath=" << FilePath(esm.event.link.target_dir)
    << "/" << esm.event.link.target_filename.data;

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  LOGE(@"Enriched link: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedRename &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

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

  LOGE(@"Enriched rename: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedUnlink &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

  ss << "action=DELETE|path=" << FilePath(esm.event.unlink.target);

  AppendProcess(ss, esm.process);
  AppendUserGroup(ss,
                  esm.process->audit_token,
                  msg.instigator_.real_user_,
                  msg.instigator_.real_group_);

  std::string s = ss.str();

  LOGE(@"Enriched delete: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeAllowList(const Message& msg,
                                                     const std::string_view hash) {
  std::stringstream ss;

  ss << "action=ALLOWLIST|pid=" << Pid(msg->process->audit_token)
     << "|pidversion=" << Pidversion(msg->process->audit_token)
     << "|sha256=" << hash;

  std::string s = ss.str();

  LOGE(@"AllowList: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeBundleHashingEvent(SNTStoredEvent* event) {
  std::stringstream ss;

  ss << "action=BUNDLE|sha256=" << event.fileSHA256
     << "|bundlehash=" << event.fileBundleHash
     << "|bundlename=" << event.fileBundleName
     << "|bundleid=" << event.fileBundleID
     << "|bundlepath=" << event.fileBundlePath
     << "|path=" << event.filePath;

  std::string s = ss.str();

  LOGE(@"BundleHashing: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace santa::santad::logs
