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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/SantaVnodeHash.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::EventDisposition;
using santa::santad::data_layer::WatchItemPathType;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::EnrichOptions;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

NSString *kBadCertHash = @"BAD_CERT_HASH";

static inline std::string Path(const es_file_t *esFile) {
  return std::string(esFile->path.data, esFile->path.length);
}

static inline std::string Path(const es_string_token_t &tok) {
  return std::string(tok.data, tok.length);
}

static inline void PushBackIfNotTruncated(std::vector<std::string> &vec, const es_file_t *esFile) {
  if (!esFile->path_truncated) {
    vec.push_back(Path(esFile));
  }
}

static inline void PushBackIfNotTruncated(std::vector<std::string> &vec, const es_file_t *dir,
                                          const es_string_token_t &name) {
  if (!dir->path_truncated) {
    vec.push_back(Path(dir) + "/" + Path(name));
  }
}

es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kNoPolicy: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kDenied: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kAllowed: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return ES_AUTH_RESULT_ALLOW;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid file access decision encountered: %d", decision);
      [NSException raise:@"Invalid FileAccessPolicyDecision"
                  format:@"Invalid FileAccessPolicyDecision: %d", decision];
  }
}

bool ShouldLogDecision(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kDenied: return true;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return true;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return true; ;
    default: return false;
  }
}

es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2) {
  // If either policy denied the operation, the operation is denied
  return ((result1 == ES_AUTH_RESULT_DENY || result2 == ES_AUTH_RESULT_DENY)
            ? ES_AUTH_RESULT_DENY
            : ES_AUTH_RESULT_ALLOW);
}

void PopulatePathTargets(const Message &msg, std::vector<std::string> &targets) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN: PushBackIfNotTruncated(targets, msg->event.open.file); break;
    case ES_EVENT_TYPE_AUTH_LINK:
      PushBackIfNotTruncated(targets, msg->event.link.source);
      PushBackIfNotTruncated(targets, msg->event.link.target_dir, msg->event.link.target_filename);
      break;
    case ES_EVENT_TYPE_AUTH_RENAME:
      if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        PushBackIfNotTruncated(targets, msg->event.rename.source);
        PushBackIfNotTruncated(targets, msg->event.rename.destination.existing_file);
      } else if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackIfNotTruncated(targets, msg->event.rename.source);
        PushBackIfNotTruncated(targets, msg->event.rename.destination.new_path.dir,
                               msg->event.rename.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for rename event: %d. Ignoring destination.",
             msg->event.rename.destination_type);
        PushBackIfNotTruncated(targets, msg->event.rename.source);
      }
      break;
    case ES_EVENT_TYPE_AUTH_UNLINK:
      PushBackIfNotTruncated(targets, msg->event.unlink.target);
      break;
    case ES_EVENT_TYPE_AUTH_CLONE:
      PushBackIfNotTruncated(targets, msg->event.clone.source);
      PushBackIfNotTruncated(targets, msg->event.link.target_dir, msg->event.clone.target_name);
      break;
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
      PushBackIfNotTruncated(targets, msg->event.exchangedata.file1);
      PushBackIfNotTruncated(targets, msg->event.exchangedata.file2);
      break;
    case ES_EVENT_TYPE_AUTH_COPYFILE:
      if (msg->event.copyfile.target_file) {
        PushBackIfNotTruncated(targets, msg->event.copyfile.source);
        PushBackIfNotTruncated(targets, msg->event.copyfile.target_file);
      } else {
        PushBackIfNotTruncated(targets, msg->event.copyfile.source);

        PushBackIfNotTruncated(targets, msg->event.copyfile.target_dir,
                               msg->event.copyfile.target_name);
      }
      break;
    default:
      [NSException
         raise:@"Unexpected event type"
        format:@"File Access Authorizer client does not handle event: %d", msg->event_type];
      exit(EXIT_FAILURE);
  }
}

@interface SNTEndpointSecurityFileAccessAuthorizer ()
@property SNTDecisionCache *decisionCache;
@property bool isSubscribed;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizer {
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
  std::shared_ptr<Enricher> _enricher;
  SantaCache<SantaVnode, NSString *> _certHashCache;
}

- (instancetype)
  initWithESAPI:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)esApi
        metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
         logger:(std::shared_ptr<santa::santad::logs::endpoint_security::Logger>)logger
     watchItems:(std::shared_ptr<WatchItems>)watchItems
       enricher:
         (std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher>)enricher
  decisionCache:(SNTDecisionCache *)decisionCache {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::santad::Processor::kFileAccessAuthorizer];
  if (self) {
    _watchItems = std::move(watchItems);
    _logger = std::move(logger);
    _enricher = std::move(enricher);

    _decisionCache = decisionCache;

    [self establishClientOrDie];

    [super enableTargetPathWatching];
    [super unmuteEverything];
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

- (FileAccessPolicyDecision)specialCaseForPolicy:(std::shared_ptr<WatchItemPolicy>)policy
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

  return FileAccessPolicyDecision::kNoPolicy;
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
  FileAccessPolicyDecision specialCase = [self specialCaseForPolicy:policy message:msg];
  if (specialCase != FileAccessPolicyDecision::kNoPolicy) {
    return specialCase;
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

  if (policy->audit_only) {
    return FileAccessPolicyDecision::kAllowedAuditOnly;
  } else {
    // TODO(xyz): Write to TTY like in exec controller?
    // TODO(xyz): Need new config item for custom message in UI
    return FileAccessPolicyDecision::kDenied;
  }
}

- (FileAccessPolicyDecision)handleMessage:(const Message &)msg
                                   target:(const std::string &)target
                                   policy:
                                     (std::optional<std::shared_ptr<WatchItemPolicy>>)optionalPolicy
                            policyVersion:(const std::string &)policyVersion {
  FileAccessPolicyDecision policyDecision = [self applyPolicy:optionalPolicy toMessage:msg];

  if (ShouldLogDecision(policyDecision)) {
    if (optionalPolicy.has_value()) {
      std::string policyNameCopy = optionalPolicy.value()->name;
      std::string policyVersionCopy = policyVersion;
      std::string targetCopy = target;

      [self asynchronouslyProcess:msg
                          handler:^(Message &&esMsg) {
                            self->_logger->LogFileAccess(
                              policyVersionCopy, policyNameCopy, esMsg,
                              self->_enricher->Enrich(*esMsg->process, EnrichOptions::kLocalOnly),
                              targetCopy, policyDecision);
                          }];

    } else {
      LOGE(@"Unexpectedly missing policy: Unable to log file access event: %s -> %s",
           Path(msg->process->executable).data(), target.c_str());
    }
  }

  return policyDecision;
}

- (void)processMessage:(const Message &)msg {
  std::vector<std::string> targets;
  PopulatePathTargets(msg, targets);
  WatchItems::VersionAndPolicies versionAndPolicies =
    self->_watchItems->FindPolciesForPaths(targets);

  es_auth_result_t policyResult = ES_AUTH_RESULT_ALLOW;
  FileAccessPolicyDecision prevDecision = FileAccessPolicyDecision::kNoPolicy;

  for (size_t i = 0; i < targets.size(); i++) {
    FileAccessPolicyDecision curDecision = [self handleMessage:msg
                                                        target:targets[i]
                                                        policy:versionAndPolicies.second[i]
                                                 policyVersion:versionAndPolicies.first];

    policyResult = CombinePolicyResults(FileAccessPolicyDecisionToESAuthResult(prevDecision),
                                        FileAccessPolicyDecisionToESAuthResult(curDecision));
    prevDecision = curDecision;
  }

  [self respondToMessage:msg
          withAuthResult:policyResult
               cacheable:false];
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
  if (!self.isSubscribed) {
    self.isSubscribed = [super subscribe:{ES_EVENT_TYPE_AUTH_OPEN}];
    [super clearCache];
  }
}

- (void)disable {
  if (self.isSubscribed) {
    if ([super unsubscribeAll]) {
      self.isSubscribed = false;
    }
    [super unmuteEverything];
  }
}

- (void)watchItemsCount:(size_t)count
               newPaths:(const std::vector<std::pair<std::string, WatchItemPathType>> &)newPaths
           removedPaths:
             (const std::vector<std::pair<std::string, WatchItemPathType>> &)removedPaths {
  if (count == 0) {
    [self disable];
  } else {
    // Stop watching removed paths
    [super unmuteTargetPaths:removedPaths];

    // Begin watching the added paths
    [super muteTargetPaths:newPaths];

    // begin receiving events (if not already)
    [self enable];
  }
}

@end
