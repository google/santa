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

#include <optional>
#include <string>

#include <time.h>
#include <uuid/uuid.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

// Forward declarations
namespace santa::santad::logs::endpoint_security::serializers {
  class Serializer;
  class BasicString;
}

namespace santa::santad::event_providers::endpoint_security {

class EnrichedFile {
public:
  EnrichedFile(
      std::optional<std::shared_ptr<std::string>> &&user,
      std::optional<std::shared_ptr<std::string>> &&group,
      std::optional<std::shared_ptr<std::string>> &&hash)
    : user_(std::move(user)),
      group_(std::move(group)),
      hash_(std::move(hash)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  std::optional<std::shared_ptr<std::string>> user_;
  std::optional<std::shared_ptr<std::string>> group_;
  std::optional<std::shared_ptr<std::string>> hash_;
};

class EnrichedProcess {
public:
  EnrichedProcess(
      std::optional<std::shared_ptr<std::string>> &&effective_user,
      std::optional<std::shared_ptr<std::string>> &&effective_group,
      std::optional<std::shared_ptr<std::string>> &&real_user,
      std::optional<std::shared_ptr<std::string>> &&real_group,
      EnrichedFile &&executable)
    : effective_user_(std::move(effective_user)),
      effective_group_(std::move(effective_group)),
      real_user_(std::move(real_user)),
      real_group_(std::move(real_group)),
      executable_(std::move(executable)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  std::optional<std::shared_ptr<std::string>> effective_user_;
  std::optional<std::shared_ptr<std::string>> effective_group_;
  std::optional<std::shared_ptr<std::string>> real_user_;
  std::optional<std::shared_ptr<std::string>> real_group_;
  EnrichedFile executable_;
};

class EnrichedClose {
public:
  EnrichedClose(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedFile &&target)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      target_(std::move(target)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedFile target_;
};

class EnrichedExchange {
public:
  EnrichedExchange(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedFile &&file1,
      EnrichedFile &&file2)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      file1_(std::move(file1)),
      file2_(std::move(file2)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedFile file1_;
  EnrichedFile file2_;
};

class EnrichedExec {
public:
  EnrichedExec(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedProcess &&target,
      std::optional<EnrichedFile> &&script,
      std::optional<EnrichedFile> working_dir)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      target_(std::move(target)),
      script_(std::move(script)),
      working_dir_(std::move(working_dir)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedProcess target_;
  std::optional<EnrichedFile> script_;
  std::optional<EnrichedFile> working_dir_;
};

class EnrichedExit {
public:
  EnrichedExit(
      Message &&es_msg,
      EnrichedProcess &&instigator)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
};

class EnrichedFork {
public:
  EnrichedFork(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedProcess &&target)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      target_(std::move(target)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedProcess target_;
};

class EnrichedLink {
public:
  EnrichedLink(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedFile &&source,
      EnrichedFile &&target_dir)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      source_(std::move(source)),
      target_dir_(std::move(target_dir)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedFile source_;
  EnrichedFile target_dir_;
};

class EnrichedRename {
public:
  EnrichedRename(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedFile &&source,
      std::optional<EnrichedFile> &&target,
      std::optional<EnrichedFile> &&target_dir)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      source_(std::move(source)),
      target_(std::move(target)),
      target_dir_(std::move(target_dir)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedFile source_;
  std::optional<EnrichedFile> target_;
  std::optional<EnrichedFile> target_dir_;
};

class EnrichedUnlink {
public:
  EnrichedUnlink(
      Message &&es_msg,
      EnrichedProcess &&instigator,
      EnrichedFile &&target)
    : es_msg_(std::move(es_msg)),
      instigator_(std::move(instigator)),
      target_(std::move(target)) {}

  // Allow serializers to access internals
  friend class santa::santad::logs::endpoint_security::serializers::BasicString;

private:
  Message es_msg_;
  EnrichedProcess instigator_;
  EnrichedFile target_;
};

using EnrichedType = std::variant<
  EnrichedClose,
  EnrichedExchange,
  EnrichedExec,
  EnrichedExit,
  EnrichedFork,
  EnrichedLink,
  EnrichedRename,
  EnrichedUnlink
>;

class EnrichedMessage {
public:
  EnrichedMessage(EnrichedType &&msg)
      : msg_(std::move(msg)) {
    uuid_generate(uuid_);
    clock_gettime(CLOCK_REALTIME, &enrichment_time_);
  }

  // Allow serializer to access internals
  friend class santa::santad::logs::endpoint_security::serializers::Serializer;

private:
  uuid_t uuid_;
  struct timespec enrichment_time_;
  EnrichedType msg_;
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
