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

/// This file groups all of the enriched message types - that is the
/// objects that are constructed to hold all enriched event data prior
/// to being logged.

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENRICHEDTYPES_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENRICHEDTYPES_H

#include <time.h>
#include <uuid/uuid.h>

#include <optional>
#include <string>
#include <variant>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa::santad::event_providers::endpoint_security {

class EnrichedFile {
 public:
  EnrichedFile(std::optional<std::shared_ptr<std::string>> &&user,
               std::optional<std::shared_ptr<std::string>> &&group,
               std::optional<std::shared_ptr<std::string>> &&hash)
      : user_(std::move(user)),
        group_(std::move(group)),
        hash_(std::move(hash)) {}

 private:
  std::optional<std::shared_ptr<std::string>> user_;
  std::optional<std::shared_ptr<std::string>> group_;
  std::optional<std::shared_ptr<std::string>> hash_;
};

class EnrichedProcess {
 public:
  EnrichedProcess(std::optional<std::shared_ptr<std::string>> &&effective_user,
                  std::optional<std::shared_ptr<std::string>> &&effective_group,
                  std::optional<std::shared_ptr<std::string>> &&real_user,
                  std::optional<std::shared_ptr<std::string>> &&real_group,
                  EnrichedFile &&executable)
      : effective_user_(std::move(effective_user)),
        effective_group_(std::move(effective_group)),
        real_user_(std::move(real_user)),
        real_group_(std::move(real_group)),
        executable_(std::move(executable)) {}

  const std::optional<std::shared_ptr<std::string>> &real_user() const {
    return real_user_;
  }
  const std::optional<std::shared_ptr<std::string>> &real_group() const {
    return real_group_;
  }

 private:
  std::optional<std::shared_ptr<std::string>> effective_user_;
  std::optional<std::shared_ptr<std::string>> effective_group_;
  std::optional<std::shared_ptr<std::string>> real_user_;
  std::optional<std::shared_ptr<std::string>> real_group_;
  EnrichedFile executable_;
};

class EnrichedEventType {
 public:
  EnrichedEventType(Message &&es_msg, EnrichedProcess &&instigator)
      : es_msg_(std::move(es_msg)), instigator_(std::move(instigator)) {}

  EnrichedEventType(EnrichedEventType &&other)
      : es_msg_(std::move(other.es_msg_)),
        instigator_(std::move(other.instigator_)) {}

  virtual ~EnrichedEventType() = default;

  const es_message_t &es_msg() const { return *es_msg_; }

  const EnrichedProcess &instigator() const { return instigator_; }

 private:
  Message es_msg_;
  EnrichedProcess instigator_;
};

class EnrichedClose : public EnrichedEventType {
 public:
  EnrichedClose(Message &&es_msg, EnrichedProcess &&instigator,
                EnrichedFile &&target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

 private:
  EnrichedFile target_;
};

class EnrichedExchange : public EnrichedEventType {
 public:
  EnrichedExchange(Message &&es_msg, EnrichedProcess &&instigator,
                   EnrichedFile &&file1, EnrichedFile &&file2)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        file1_(std::move(file1)),
        file2_(std::move(file2)) {}

 private:
  EnrichedFile file1_;
  EnrichedFile file2_;
};

class EnrichedExec : public EnrichedEventType {
 public:
  EnrichedExec(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedProcess &&target, std::optional<EnrichedFile> &&script,
               std::optional<EnrichedFile> working_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)),
        script_(std::move(script)),
        working_dir_(std::move(working_dir)) {}

 private:
  EnrichedProcess target_;
  std::optional<EnrichedFile> script_;
  std::optional<EnrichedFile> working_dir_;
};

class EnrichedExit : public EnrichedEventType {
 public:
  EnrichedExit(Message &&es_msg, EnrichedProcess &&instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}
};

class EnrichedFork : public EnrichedEventType {
 public:
  EnrichedFork(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedProcess &&target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

 private:
  EnrichedProcess target_;
};

class EnrichedLink : public EnrichedEventType {
 public:
  EnrichedLink(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedFile &&source, EnrichedFile &&target_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)),
        target_dir_(std::move(target_dir)) {}

 private:
  EnrichedFile source_;
  EnrichedFile target_dir_;
};

class EnrichedRename : public EnrichedEventType {
 public:
  EnrichedRename(Message &&es_msg, EnrichedProcess &&instigator,
                 EnrichedFile &&source, std::optional<EnrichedFile> &&target,
                 std::optional<EnrichedFile> &&target_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)),
        target_(std::move(target)),
        target_dir_(std::move(target_dir)) {}

 private:
  EnrichedFile source_;
  std::optional<EnrichedFile> target_;
  std::optional<EnrichedFile> target_dir_;
};

class EnrichedUnlink : public EnrichedEventType {
 public:
  EnrichedUnlink(Message &&es_msg, EnrichedProcess &&instigator,
                 EnrichedFile &&target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

 private:
  EnrichedFile target_;
};

using EnrichedType =
    std::variant<EnrichedClose, EnrichedExchange, EnrichedExec, EnrichedExit,
                 EnrichedFork, EnrichedLink, EnrichedRename, EnrichedUnlink>;

class EnrichedMessage {
 public:
  EnrichedMessage(EnrichedType &&msg) : msg_(std::move(msg)) {
    uuid_generate(uuid_);
    clock_gettime(CLOCK_REALTIME, &enrichment_time_);
  }

  const EnrichedType &GetEnrichedMessage() { return msg_; }

 private:
  uuid_t uuid_;
  struct timespec enrichment_time_;
  EnrichedType msg_;
};

}  // namespace santa::santad::event_providers::endpoint_security

#endif
