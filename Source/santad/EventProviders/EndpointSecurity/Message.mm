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

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

namespace santa::santad::event_providers::endpoint_security {

Message::Message(std::shared_ptr<EndpointSecurityAPI> esapi, const es_message_t *es_msg)
    : esapi_(std::move(esapi)), es_msg_(es_msg), process_token_(std::nullopt) {
  esapi_->RetainMessage(es_msg);
  UpdateStatState(santa::santad::StatChangeStep::kMessageCreate);
}

Message::~Message() {
  if (es_msg_) {
    esapi_->ReleaseMessage(es_msg_);
  }
}

Message::Message(Message &&other) {
  esapi_ = std::move(other.esapi_);
  es_msg_ = other.es_msg_;
  other.es_msg_ = nullptr;
  process_token_ = std::move(other.process_token_);
  other.process_token_ = std::nullopt;
  stat_change_step_ = other.stat_change_step_;
  stat_result_ = other.stat_result_;
}

Message::Message(const Message &other) {
  esapi_ = other.esapi_;
  es_msg_ = other.es_msg_;
  esapi_->RetainMessage(es_msg_);
  process_token_ = other.process_token_;
  stat_change_step_ = other.stat_change_step_;
  stat_result_ = other.stat_result_;
}

void Message::UpdateStatState(santa::santad::StatChangeStep step) const {
  // Only update state for AUTH EXEC events and if no previous change was detected
  if (es_msg_->event_type == ES_EVENT_TYPE_AUTH_EXEC &&
      stat_change_step_ == santa::santad::StatChangeStep::kNoChange &&
      // Note: The following checks are required due to tests that only
      // partially construct an es_message_t.
      es_msg_->event.exec.target && es_msg_->event.exec.target->executable) {
    struct stat &es_sb = es_msg_->event.exec.target->executable->stat;
    struct stat sb;
    errno = 0;
    int ret = stat(es_msg_->event.exec.target->executable->path.data, &sb);
    // If stat failed, or if devno/inode changed, update state.
    if (ret != 0 || es_sb.st_ino != sb.st_ino || es_sb.st_dev != sb.st_dev) {
      stat_change_step_ = step;
      // Determine the specific condition that failed for tracking purposes
      if (ret != 0) {
        stat_result_ = santa::santad::StatResult::kStatError;
      } else {
        stat_result_ = santa::santad::StatResult::kDevnoInodeMismatch;
      }
    }
  }
}

void Message::SetProcessToken(process_tree::ProcessToken tok) {
  process_token_ = std::move(tok);
}

std::string Message::ParentProcessName() const {
  return GetProcessName(es_msg_->process->ppid);
}

std::string Message::GetProcessName(pid_t pid) const {
  // Note: proc_name() accesses the `pbi_name` field of `struct proc_bsdinfo`. The size of `pname`
  // here is meant to match the size of `pbi_name`, and one extra byte ensure zero-terminated.
  char pname[MAXCOMLEN * 2 + 1] = {};
  if (proc_name(pid, pname, sizeof(pname)) > 0) {
    return std::string(pname);
  } else {
    return std::string("");
  }
}

}  // namespace santa::santad::event_providers::endpoint_security
