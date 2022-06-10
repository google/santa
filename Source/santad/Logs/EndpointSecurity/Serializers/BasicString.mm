#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"

#include <sstream>

#include <bsm/libbsm.h>
#include <libgen.h>
#include <mach/message.h>
#include <sys/param.h>

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedLink;
using santa::santad::event_providers::endpoint_security::EnrichedRename;
using santa::santad::event_providers::endpoint_security::EnrichedUnlink;

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
  return audit_token_to_ruid(tok);
}

inline void AppendProcess(std::stringstream& ss,
                          const es_process_t* es_proc) {
  char bname[MAXPATHLEN];
  ss << "|pid=" << Pid(es_proc->audit_token)
     << "|ppid=" << es_proc->original_ppid
     << "|process=" << basename_r(FilePath(es_proc->executable).data(), bname)
     << "|processpath=" << FilePath(es_proc->executable);
}

inline void AppendUserGroup(std::stringstream& ss,
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

  LOGE(@"Enriched unlink: %s", s.c_str());

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

  LOGE(@"Enriched link: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> BasicString::SerializeMessage(const EnrichedExec &msg) {
  const es_message_t &esm = *msg.es_msg_;
  std::stringstream ss;

  ss << "action=EXEC|pid=" << audit_token_to_pid(esm.process->audit_token)
    << "|instigator=" << esm.process->executable->path.data
    << "|new_image=" << esm.event.exec.target->executable->path.data;

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

  LOGE(@"Enriched link: %s", s.c_str());

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

  LOGE(@"Enriched unlink: %s", s.c_str());

  return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace santa::santad::logs
