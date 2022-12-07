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

#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <Kernel/kern/cs_blobs.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#include <sys/fcntl.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <memory>
#include <optional>
#include <set>
#include <type_traits>
#include <variant>

#import "Source/common/SNTConfigurator.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/SantaVnodeHash.h"
#include "Source/common/Unit.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::common::Unit;
using santa::santad::EventDisposition;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

// Currently, all events used here have at least one target path that is represented
// by an `es_file_t` and this is held as the first pair item as an `std::string_view`
// since new memory isn't needed.
// For events that have a second target path, the `std::variant` will either be an
// `std::string_view` if possible, otherwise if a new string must be constructed an
// `std::string` is used.
using PathTargets = std::pair<std::string_view, std::variant<std::string_view, std::string, Unit>>;

NSString *kBadCertHash = @"BAD_CERT_HASH";

static inline std::string_view PathView(const es_file_t *esFile) {
  return std::string_view(esFile->path.data, esFile->path.length);
}

static inline std::string_view PathView(const es_string_token_t &tok) {
  return std::string_view(tok.data, tok.length);
}

static inline std::string Path(const es_file_t *dir, const es_string_token_t &name) {
  return std::string(PathView(dir)) + std::string(PathView(name));
}

es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision disposition) {
  switch (disposition) {
    case FileAccessPolicyDecision::kNoPolicy: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kDenied: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kAllowed: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return ES_AUTH_RESULT_ALLOW;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid file access disposition encountered: %d", disposition);
      [NSException raise:@"Invalid FileAccessPolicyDecision"
                  format:@"Invalid FileAccessPolicyDecision: %d", disposition];
  }
}

es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2) {
  // If either policy denied the operation, the operation is denied
  return ((result1 == ES_AUTH_RESULT_DENY || result2 == ES_AUTH_RESULT_DENY)
            ? ES_AUTH_RESULT_DENY
            : ES_AUTH_RESULT_ALLOW);
}

PathTargets GetPathTargets(const Message &msg) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN: return {PathView(msg->event.open.file), Unit{}};
    case ES_EVENT_TYPE_AUTH_LINK:
      return {PathView(msg->event.link.source),
              Path(msg->event.link.target_dir, msg->event.link.target_filename)};
    case ES_EVENT_TYPE_AUTH_RENAME:
      if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        return {PathView(msg->event.rename.source),
                PathView(msg->event.rename.destination.existing_file)};
      } else if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        return {PathView(msg->event.rename.source),
                Path(msg->event.rename.destination.new_path.dir,
                     msg->event.rename.destination.new_path.filename)};
      } else {
        LOGW(@"Unexpected destination type for rename event: %d. Ignoring destination.",
             msg->event.rename.destination_type);
        return {PathView(msg->event.rename.source), Unit{}};
      }
    case ES_EVENT_TYPE_AUTH_UNLINK: return {PathView(msg->event.unlink.target), Unit{}};
    case ES_EVENT_TYPE_AUTH_CLONE:
      return {PathView(msg->event.clone.source),
              Path(msg->event.link.target_dir, msg->event.clone.target_name)};
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
      return {PathView(msg->event.exchangedata.file1), PathView(msg->event.exchangedata.file2)};
    case ES_EVENT_TYPE_AUTH_COPYFILE:
      if (msg->event.copyfile.target_file) {
        return {PathView(msg->event.copyfile.source), PathView(msg->event.copyfile.target_file)};
      } else {
        return {PathView(msg->event.copyfile.source),
                Path(msg->event.copyfile.target_dir, msg->event.copyfile.target_name)};
      }
    default:
      [NSException
         raise:@"Unexpected event type"
        format:@"File Access Authorizer client does not handle event: %d", msg->event_type];
      exit(EXIT_FAILURE);
  }
}

@interface SNTEndpointSecurityFileAccessAuthorizer ()
@property SNTDecisionCache *decisionCache;
@property BOOL isSubscribed;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizer {
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
  SantaCache<SantaVnode, NSString *> _certHashCache;
}

- (instancetype)
  initWithESAPI:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)esApi
        metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
         logger:(std::shared_ptr<santa::santad::logs::endpoint_security::Logger>)logger
     watchItems:(std::shared_ptr<WatchItems>)watchItems
  decisionCache:(SNTDecisionCache *)decisionCache {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::santad::Processor::kFileAccessAuthorizer];
  if (self) {
    _watchItems = std::move(watchItems);
    _logger = std::move(logger);

    _decisionCache = decisionCache;

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"FileAccessAuthorizer";
}

- (NSString *)getCertificateHash:(es_file_t *)esFile {
  // First see if we've already cached this value
  SantaVnode vnodeID = SantaVnode::VnodeForFile(esFile);
  NSString *result = self->_certHashCache.get(vnodeID);
  if (!result) {
    // If this wasn't already cached, try finding a cached SNTCachedDecision
    SNTCachedDecision *cd = [self.decisionCache cachedDecisionForFile:esFile->stat];
    if (cd) {
      // There was an existing cached decision, use its cert hash
      result = cd.certSHA256;
    } else {
      // If the cached decision didn't exist, try a manual lookup
      NSError *e;
      MOLCodesignChecker *csInfo =
        [[MOLCodesignChecker alloc] initWithBinaryPath:@(esFile->path.data) error:&e];
      if (!e) {
        result = csInfo.leafCertificate.SHA256;
      }
    }

    if (!result.length) {
      // If result is still nil, there isn't much recourse... We will
      // assume that this error isn't transient and set a terminal value
      // in the cache to prevent continous attempts to lookup cert hash.
      result = kBadCertHash;
    }

    // Finally, add the result to the cache to prevent future lookups
    self->_certHashCache.set(vnodeID, result);
  }

  return result;
}

- (std::optional<FileAccessPolicyDecision>)specialCaseForPolicy:
                                             (std::shared_ptr<WatchItemPolicy>)policy
                                                        message:(const Message &)msg {
  constexpr int openFlagsIndicatingWrite = FWRITE | O_APPEND | O_TRUNC;

  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN:
      // If the policy is write-only, but the operation isn't a write action, it's allowed
      if (policy->write_only && !(msg->event.open.fflag & openFlagsIndicatingWrite)) {
        return FileAccessPolicyDecision::kAllowed;
      }

      break;
    case ES_EVENT_TYPE_AUTH_LINK:
    case ES_EVENT_TYPE_AUTH_RENAME:
    case ES_EVENT_TYPE_AUTH_UNLINK:
    case ES_EVENT_TYPE_AUTH_CLONE:
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
    case ES_EVENT_TYPE_AUTH_COPYFILE:
      // TODO(xyz): Handle special cases for more event types
      break;
    default:
      [NSException raise:@"Unexpected event type"
                  format:@"Received unexpected event type in the file access authorizer: %d",
                         msg->event_type];
      exit(EXIT_FAILURE);
  }

  return std::nullopt;
}

// The operation is allowed when:
//   - No policy exists
//   - The policy is write-only, but the operation is read-only
//   - The operation was instigated by an allowed process
//   - If the instigating process is signed, the codesignature is valid
// Otherwise the operation is denied.
- (FileAccessPolicyDecision)applyPolicy:
                              (std::optional<std::shared_ptr<WatchItemPolicy>>)optionalPolicy
                              toMessage:(const Message &)msg {
  // If no policy exists, everything is allowed
  if (!optionalPolicy.has_value()) {
    return FileAccessPolicyDecision::kNoPolicy;
  }

  // If the process is signed but has an invalid signature, it is denied
  if (((msg->process->codesigning_flags & (CS_SIGNED | CS_VALID)) == CS_SIGNED) &&
      [[SNTConfigurator configurator] enableBadSignatureProtection]) {
    // TODO(mlw): Think about how to make stronger guarantees here to handle
    // programs becoming invalid after first being granted access. Maybe we
    // should only allow things that have hardened runtime flags set?
    return FileAccessPolicyDecision::kDeniedInvalidSignature;
  }

  std::shared_ptr<WatchItemPolicy> policy = optionalPolicy.value();

  // Check if this action contains any special case that would produce
  // an immediate result.
  std::optional<FileAccessPolicyDecision> specialCase = [self specialCaseForPolicy:policy
                                                                           message:msg];
  if (specialCase.has_value()) {
    return specialCase.value();
  }

  // Check if the instigating process path opening the file is allowed
  if (policy->allowed_binary_paths.count(msg->process->executable->path.data) > 0) {
    return FileAccessPolicyDecision::kAllowed;
  }

  // TeamID, CDHash, and Cert Hashes are only valid if the binary is signed
  if (msg->process->codesigning_flags & CS_SIGNED) {
    // Check if the instigating process has an allowed TeamID
    if (msg->process->team_id.data &&
        policy->allowed_team_ids.count(msg->process->team_id.data) > 0) {
      return FileAccessPolicyDecision::kAllowed;
    }

    if (policy->allowed_cdhashes.size() > 0) {
      // Check if the instigating process has an allowed CDHash
      std::array<uint8_t, CS_CDHASH_LEN> bytes;
      std::copy(std::begin(msg->process->cdhash), std::end(msg->process->cdhash),
                std::begin(bytes));
      if (policy->allowed_cdhashes.count(bytes) > 0) {
        return FileAccessPolicyDecision::kAllowed;
      }
    }

    if (policy->allowed_certificates_sha256.size() > 0) {
      // Check if the instigating process has an allowed certificate hash
      NSString *result = [self getCertificateHash:msg->process->executable];
      if (result && policy->allowed_certificates_sha256.count([result UTF8String])) {
        return FileAccessPolicyDecision::kAllowed;
      }
    }
  }

  // If we get here, a policy existed and no exceptions were found. Log it.
  self->_logger->LogAccess(msg);

  // If the policy was audit-only, don't deny the operation
  if (policy->audit_only) {
    return FileAccessPolicyDecision::kAllowedAuditOnly;
  } else {
    // TODO(xyz): Write to TTY like in exec controller?
    // TODO(xyz): Need new config item for custom message in UI
    return FileAccessPolicyDecision::kDenied;
  }
}

- (void)processMessage:(const Message &)msg {
  PathTargets targets = GetPathTargets(msg);

  std::optional<std::shared_ptr<WatchItemPolicy>> policy1 =
    self->_watchItems->FindPolicyForPath(targets.first.data());

  std::shared_ptr<WatchItems> watchItems = self->_watchItems;
  std::optional<std::shared_ptr<WatchItemPolicy>> policy2 = std::visit(
    [&watchItems](const auto &arg) -> std::optional<std::shared_ptr<WatchItemPolicy>> {
      using T = std::decay_t<decltype(arg)>;
      if constexpr (std::is_same_v<T, std::string>) {
        return watchItems->FindPolicyForPath(arg.c_str());
      } else if constexpr (std::is_same_v<T, std::string_view>) {
        return watchItems->FindPolicyForPath(arg.data());
      } else {
        return std::nullopt;
      }
    },
    targets.second);

  FileAccessPolicyDecision policy1Decision = [self applyPolicy:policy1 toMessage:msg];
  FileAccessPolicyDecision policy2Decision = [self applyPolicy:policy2 toMessage:msg];
  es_auth_result_t policyResult =
    CombinePolicyResults(FileAccessPolicyDecisionToESAuthResult(policy1Decision),
                         FileAccessPolicyDecisionToESAuthResult(policy2Decision));

  [self respondToMessage:msg
          withAuthResult:policyResult
               cacheable:(policyResult == ES_AUTH_RESULT_ALLOW)];
}

- (void)handleMessage:(santa::santad::event_providers::endpoint_security::Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  [self processMessage:std::move(esMsg)
               handler:^(const Message &msg) {
                 [self processMessage:msg];
                 recordEventMetrics(EventDisposition::kProcessed);
               }];
}

- (void)enable {
  // TODO(xyz): Will be expanding support to many more event types soon:
  // ES_EVENT_TYPE_AUTH_LINK
  // ES_EVENT_TYPE_AUTH_RENAME
  // ES_EVENT_TYPE_AUTH_UNLINK
  // ES_EVENT_TYPE_AUTH_CLONE
  // ES_EVENT_TYPE_AUTH_EXCHANGEDATA
  // ES_EVENT_TYPE_AUTH_COPYFILE
  [super subscribeAndClearCache:{ES_EVENT_TYPE_AUTH_OPEN}];
}

@end
