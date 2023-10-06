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

#include <optional>
#include <string>
#include <variant>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa::santad::event_providers::endpoint_security {

class EnrichedFile {
 public:
  EnrichedFile()
      : user_(std::nullopt), group_(std::nullopt), hash_(std::nullopt) {}

  EnrichedFile(std::optional<std::shared_ptr<std::string>> &&user,
               std::optional<std::shared_ptr<std::string>> &&group,
               std::optional<std::shared_ptr<std::string>> &&hash)
      : user_(std::move(user)),
        group_(std::move(group)),
        hash_(std::move(hash)) {}

  EnrichedFile(EnrichedFile &&other)
      : user_(std::move(other.user_)),
        group_(std::move(other.group_)),
        hash_(std::move(other.hash_)) {}

  // Note: Move assignment could be safely implemented but not currently needed
  EnrichedFile &operator=(EnrichedFile &&other) = delete;

  EnrichedFile(const EnrichedFile &other) = delete;
  EnrichedFile &operator=(const EnrichedFile &other) = delete;

  const std::optional<std::shared_ptr<std::string>> &user() const {
    return user_;
  }
  const std::optional<std::shared_ptr<std::string>> &group() const {
    return group_;
  }

 private:
  std::optional<std::shared_ptr<std::string>> user_;
  std::optional<std::shared_ptr<std::string>> group_;
  std::optional<std::shared_ptr<std::string>> hash_;
};

class EnrichedProcess {
 public:
  EnrichedProcess()
      : effective_user_(std::nullopt),
        effective_group_(std::nullopt),
        real_user_(std::nullopt),
        real_group_(std::nullopt) {}

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

  EnrichedProcess(EnrichedProcess &&other)
      : effective_user_(std::move(other.effective_user_)),
        effective_group_(std::move(other.effective_group_)),
        real_user_(std::move(other.real_user_)),
        real_group_(std::move(other.real_group_)),
        executable_(std::move(other.executable_)) {}

  // Note: Move assignment could be safely implemented but not currently needed
  EnrichedProcess &operator=(EnrichedProcess &&other) = delete;

  EnrichedProcess(const EnrichedProcess &other) = delete;
  EnrichedProcess &operator=(const EnrichedProcess &other) = delete;

  const std::optional<std::shared_ptr<std::string>> &effective_user() const {
    return effective_user_;
  }
  const std::optional<std::shared_ptr<std::string>> &effective_group() const {
    return effective_group_;
  }
  const std::optional<std::shared_ptr<std::string>> &real_user() const {
    return real_user_;
  }
  const std::optional<std::shared_ptr<std::string>> &real_group() const {
    return real_group_;
  }
  const EnrichedFile &executable() const { return executable_; }

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
      : es_msg_(std::move(es_msg)), instigator_(std::move(instigator)) {
    clock_gettime(CLOCK_REALTIME, &enrichment_time_);
  }

  EnrichedEventType(EnrichedEventType &&other)
      : es_msg_(std::move(other.es_msg_)),
        instigator_(std::move(other.instigator_)),
        enrichment_time_(std::move(other.enrichment_time_)) {}

  // Note: Move assignment could be safely implemented but not currently needed
  // so no sense in implementing across all child classes
  EnrichedEventType &operator=(EnrichedEventType &&other) = delete;

  EnrichedEventType(const EnrichedEventType &other) = delete;
  EnrichedEventType &operator=(const EnrichedEventType &other) = delete;

  virtual ~EnrichedEventType() = default;

  const es_message_t &es_msg() const { return *es_msg_; }
  const EnrichedProcess &instigator() const { return instigator_; }
  struct timespec enrichment_time() const {
    // No reason to return a reference
    return enrichment_time_;
  }

 private:
  Message es_msg_;
  EnrichedProcess instigator_;
  struct timespec enrichment_time_;
};

class EnrichedClose : public EnrichedEventType {
 public:
  EnrichedClose(Message &&es_msg, EnrichedProcess &&instigator,
                EnrichedFile &&target)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        target_(std::move(target)) {}

  EnrichedClose(EnrichedClose &&other)
      : EnrichedEventType(std::move(other)),
        target_(std::move(other.target_)) {}

  EnrichedClose(const EnrichedClose &other) = delete;

  const EnrichedFile &target() const { return target_; }

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

  EnrichedExchange(EnrichedExchange &&other)
      : EnrichedEventType(std::move(other)),
        file1_(std::move(other.file1_)),
        file2_(std::move(other.file2_)) {}

  EnrichedExchange(const EnrichedExchange &other) = delete;

  const EnrichedFile &file1() const { return file1_; }
  const EnrichedFile &file2() const { return file2_; }

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

  EnrichedExec(EnrichedExec &&other)
      : EnrichedEventType(std::move(other)),
        target_(std::move(other.target_)),
        script_(std::move(other.script_)),
        working_dir_(std::move(other.working_dir_)) {}

  EnrichedExec(const EnrichedExec &other) = delete;

  const EnrichedProcess &target() const { return target_; }
  const std::optional<EnrichedFile> &script() const { return script_; }
  const std::optional<EnrichedFile> &working_dir() const {
    return working_dir_;
  }

 private:
  EnrichedProcess target_;
  std::optional<EnrichedFile> script_;
  std::optional<EnrichedFile> working_dir_;
};

class EnrichedExit : public EnrichedEventType {
 public:
  EnrichedExit(Message &&es_msg, EnrichedProcess &&instigator)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}

  EnrichedExit(EnrichedExit &&other) : EnrichedEventType(std::move(other)) {}

  EnrichedExit(const EnrichedExit &other) = delete;
};

class EnrichedFork : public EnrichedEventType {
 public:
  EnrichedFork(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedProcess &&child)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        child_(std::move(child)) {}

  EnrichedFork(EnrichedFork &&other)
      : EnrichedEventType(std::move(other)), child_(std::move(other.child_)) {}

  EnrichedFork(const EnrichedFork &other) = delete;

  const EnrichedProcess &child() const { return child_; }

 private:
  EnrichedProcess child_;
};

class EnrichedLink : public EnrichedEventType {
 public:
  EnrichedLink(Message &&es_msg, EnrichedProcess &&instigator,
               EnrichedFile &&source, EnrichedFile &&target_dir)
      : EnrichedEventType(std::move(es_msg), std::move(instigator)),
        source_(std::move(source)),
        target_dir_(std::move(target_dir)) {}

  EnrichedLink(EnrichedLink &&other)
      : EnrichedEventType(std::move(other)),
        source_(std::move(other.source_)),
        target_dir_(std::move(other.target_dir_)) {}

  EnrichedLink(const EnrichedLink &other) = delete;

  const EnrichedFile &source() const { return source_; }

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

  EnrichedRename(EnrichedRename &&other)
      : EnrichedEventType(std::move(other)),
        source_(std::move(other.source_)),
        target_(std::move(other.target_)),
        target_dir_(std::move(other.target_dir_)) {}

  EnrichedRename(const EnrichedRename &other) = delete;

  const EnrichedFile &source() const { return source_; }

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

  EnrichedUnlink(EnrichedUnlink &&other)
      : EnrichedEventType(std::move(other)),
        target_(std::move(other.target_)) {}

  EnrichedUnlink(const EnrichedUnlink &other) = delete;

  const EnrichedFile &target() const { return target_; }

 private:
  EnrichedFile target_;
};

class EnrichedCSInvalidated : public EnrichedEventType {
  public:
    EnrichedCSInvalidated(Message &&es_msg, EnrichedProcess &&instigator) : EnrichedEventType(std::move(es_msg), std::move(instigator)) {}
    EnrichedCSInvalidated(EnrichedCSInvalidated &&other)
      : EnrichedEventType(std::move(other)){}
    EnrichedCSInvalidated(const EnrichedCSInvalidated &other) = delete;
};

using EnrichedType =
    std::variant<EnrichedClose, EnrichedExchange, EnrichedExec, EnrichedExit,
                 EnrichedFork, EnrichedLink, EnrichedRename, EnrichedUnlink, 
                 EnrichedCSInvalidated>;

class EnrichedMessage {
 public:
  EnrichedMessage(EnrichedType &&msg) : msg_(std::move(msg)) {}

  const EnrichedType &GetEnrichedMessage() { return msg_; }

 private:
  EnrichedType msg_;
};



}  // namespace santa::santad::event_providers::endpoint_security

#endif
