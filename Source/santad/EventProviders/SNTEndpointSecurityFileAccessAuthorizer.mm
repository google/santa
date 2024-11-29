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
#include <bsm/libbsm.h>
#include <sys/fcntl.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

#include "Source/common/Platform.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/SNTFileAccessEvent.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTStrengthify.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/SantaVnodeHash.h"
#include "Source/common/String.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/RateLimiter.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

using santa::EndpointSecurityAPI;
using santa::Enricher;
using santa::EnrichOptions;
using santa::EventDisposition;
using santa::FileAccessMetricStatus;
using santa::Logger;
using santa::Message;
using santa::Metrics;
using santa::OptionalStringToNSString;
using santa::RateLimiter;
using santa::StringToNSString;
using santa::TTYWriter;
using santa::WatchItemPathType;
using santa::WatchItemPolicy;
using santa::WatchItems;

NSString *kBadCertHash = @"BAD_CERT_HASH";

static constexpr uint32_t kOpenFlagsIndicatingWrite = FWRITE | O_APPEND | O_TRUNC;
static constexpr uint16_t kDefaultRateLimitQPS = 50;

// Small structure to hold a complete event path target being operated upon and
// a bool indicating whether the path is a readable target (e.g. a file being
// opened or cloned)
struct PathTarget {
  std::string path;
  bool isReadable;
  std::optional<std::pair<dev_t, ino_t>> devnoIno;
};

// This is a bespoke cache for mapping processes to a set of values. It has
// similar semantics to SantaCache in terms of clearing the cache keys and
// values when max sizes are reached.
//
// TODO: We need a proper LRU cache
//
// NB: This exists instead of using SantaCache for two main reasons:
//     1.) SantaCache doesn't efficiently support non-primitive value types.
//         Since the value of each key needs to be a set, we want to refrain
//         from having to unnecessarily copy the value.
//     2.) SantaCache doesn't support size limits on value types
template <typename ValueT>
class ProcessSet {
  using FileSet = absl::flat_hash_set<ValueT>;

 public:
  ProcessSet() {
    q_ = dispatch_queue_create(
      "com.google.santa.daemon.faa",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                              QOS_CLASS_USER_INTERACTIVE, 0));
  };

  // Add the given target to the set of files a process can read
  void Set(const es_process_t *proc, std::function<ValueT()> valueBlock) {
    if (!valueBlock) {
      return;
    }

    dispatch_sync(q_, ^{
      std::pair<pid_t, pid_t> pidPidver = {audit_token_to_pid(proc->audit_token),
                                           audit_token_to_pidversion(proc->audit_token)};
      SetLocked(pidPidver, valueBlock());
    });
  }

  // Remove the given process from the cache
  void Remove(const es_process_t *proc) {
    std::pair<pid_t, pid_t> pidPidver = {audit_token_to_pid(proc->audit_token),
                                         audit_token_to_pidversion(proc->audit_token)};
    dispatch_sync(q_, ^{
      cache_.erase(pidPidver);
    });
  }

  // Check if the set of files for a given process contains the given file
  bool Exists(const es_process_t *proc, std::function<ValueT()> valueBlock) {
    return ExistsOrSet(proc, valueBlock, false);
  }

  // Check if the ValueT set for a given process contains the given file, and
  // if not, set it. Both steps are done atomically.
  bool ExistsOrSet(const es_process_t *proc, std::function<ValueT()> valueBlock) {
    return ExistsOrSet(proc, valueBlock, true);
  }

  // Clear all cache entries
  void Clear() {
    dispatch_sync(q_, ^{
      ClearLocked();
    });
  }

 private:
  // Remove everything in the cache.
  void ClearLocked() { cache_.clear(); }

  void SetLocked(std::pair<pid_t, pid_t> pidPidver, ValueT value) {
    // If we hit the size limit, clear the cache to prevent unbounded growth
    if (cache_.size() >= kMaxCacheSize) {
      ClearLocked();
    }

    FileSet &fs = cache_[std::move(pidPidver)];

    // If we hit the per-entry size limit, clear the entry to prevent unbounded growth
    if (fs.size() >= kMaxCacheEntrySize) {
      fs.clear();
    }

    fs.insert(value);
  }

  bool ExistsOrSet(const es_process_t *proc, std::function<ValueT()> valueBlock, bool shouldSet) {
    std::pair<pid_t, pid_t> pidPidver = {audit_token_to_pid(proc->audit_token),
                                         audit_token_to_pidversion(proc->audit_token)};

    __block bool exists = false;

    dispatch_sync(q_, ^{
      ValueT value = valueBlock();
      const auto &iter = cache_.find(pidPidver);

      if (iter != cache_.end() && iter->second.count(value) > 0) {
        exists = true;
      } else if (shouldSet) {
        SetLocked(pidPidver, value);
      }
    });

    return exists;
  }

  dispatch_queue_t q_;
  absl::flat_hash_map<std::pair<pid_t, pid_t>, FileSet> cache_;

  // Cache limits are merely meant to protect against unbounded growth. In practice,
  // the observed cache size is typically small for normal WatchItems rules (those
  // that do not target high-volume paths). The per entry size was observed to vary
  // quite dramatically based on the type of process (e.g. large, complex applications
  // were observed to frequently have several thousands of entries).
  static constexpr size_t kMaxCacheSize = 512;
  static constexpr size_t kMaxCacheEntrySize = 8192;
};

static inline std::string Path(const es_file_t *esFile) {
  return std::string(esFile->path.data, esFile->path.length);
}

static inline std::string Path(const es_string_token_t &tok) {
  return std::string(tok.data, tok.length);
}

static inline void PushBackIfNotTruncated(std::vector<PathTarget> &vec, const es_file_t *esFile,
                                          bool isReadable = false) {
  if (!esFile->path_truncated) {
    vec.push_back({Path(esFile), isReadable,
                   isReadable ? std::make_optional<std::pair<dev_t, ino_t>>(
                                  {esFile->stat.st_dev, esFile->stat.st_ino})
                              : std::nullopt});
  }
}

// Note: This variant of PushBackIfNotTruncated can never be marked "isReadable"
static inline void PushBackIfNotTruncated(std::vector<PathTarget> &vec, const es_file_t *dir,
                                          const es_string_token_t &name) {
  if (!dir->path_truncated) {
    vec.push_back({Path(dir) + "/" + Path(name), false, std::nullopt});
  }
}

es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kNoPolicy: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kDenied: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kAllowed: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kAllowedReadAccess: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return ES_AUTH_RESULT_ALLOW;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid file access decision encountered: %d", static_cast<int>(decision));
      [NSException raise:@"Invalid FileAccessPolicyDecision"
                  format:@"Invalid FileAccessPolicyDecision: %d", static_cast<int>(decision)];
  }
}

bool IsBlockDecision(FileAccessPolicyDecision decision) {
  return decision == FileAccessPolicyDecision::kDenied ||
         decision == FileAccessPolicyDecision::kDeniedInvalidSignature;
}

FileAccessPolicyDecision ApplyOverrideToDecision(FileAccessPolicyDecision decision,
                                                 SNTOverrideFileAccessAction overrideAction) {
  switch (overrideAction) {
    // When no override should be applied, return the decision unmodified
    case SNTOverrideFileAccessActionNone: return decision;

    // When the decision should be overridden to be audit only, only change the
    // decision if it was going to deny the operation.
    case SNTOverrideFileAccessActionAuditOnly:
      if (IsBlockDecision(decision)) {
        return FileAccessPolicyDecision::kAllowedAuditOnly;
      } else {
        return decision;
      }

    // If the override action is to disable policy, return a decision that will
    // be treated as if no policy applied to the operation.
    case SNTOverrideFileAccessActionDiable: return FileAccessPolicyDecision::kNoPolicy;

    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid override file access action encountered: %d",
           static_cast<int>(overrideAction));
      [NSException
         raise:@"Invalid SNTOverrideFileAccessAction"
        format:@"Invalid SNTOverrideFileAccessAction: %d", static_cast<int>(overrideAction)];
  }
}

bool ShouldLogDecision(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kDenied: return true;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return true;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return true;
    default: return false;
  }
}

bool ShouldNotifyUserDecision(FileAccessPolicyDecision decision) {
  return ShouldLogDecision(decision) && decision != FileAccessPolicyDecision::kAllowedAuditOnly;
}

es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2) {
  // If either policy denied the operation, the operation is denied
  return ((result1 == ES_AUTH_RESULT_DENY || result2 == ES_AUTH_RESULT_DENY)
            ? ES_AUTH_RESULT_DENY
            : ES_AUTH_RESULT_ALLOW);
}

void PopulatePathTargets(const Message &msg, std::vector<PathTarget> &targets) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE:
      PushBackIfNotTruncated(targets, msg->event.clone.source, true);
      PushBackIfNotTruncated(targets, msg->event.clone.target_dir, msg->event.clone.target_name);
      break;

    case ES_EVENT_TYPE_AUTH_CREATE:
      // AUTH CREATE events should always be ES_DESTINATION_TYPE_NEW_PATH
      if (msg->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackIfNotTruncated(targets, msg->event.create.destination.new_path.dir,
                               msg->event.create.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for create event: %d. Ignoring target.",
             msg->event.create.destination_type);
      }
      break;

    case ES_EVENT_TYPE_AUTH_COPYFILE:
      PushBackIfNotTruncated(targets, msg->event.copyfile.source, true);
      if (msg->event.copyfile.target_file) {
        PushBackIfNotTruncated(targets, msg->event.copyfile.target_file);
      } else {
        PushBackIfNotTruncated(targets, msg->event.copyfile.target_dir,
                               msg->event.copyfile.target_name);
      }
      break;

    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
      PushBackIfNotTruncated(targets, msg->event.exchangedata.file1);
      PushBackIfNotTruncated(targets, msg->event.exchangedata.file2);
      break;

    case ES_EVENT_TYPE_AUTH_LINK:
      PushBackIfNotTruncated(targets, msg->event.link.source);
      PushBackIfNotTruncated(targets, msg->event.link.target_dir, msg->event.link.target_filename);
      break;

    case ES_EVENT_TYPE_AUTH_OPEN:
      PushBackIfNotTruncated(targets, msg->event.open.file, true);
      break;

    case ES_EVENT_TYPE_AUTH_RENAME:
      PushBackIfNotTruncated(targets, msg->event.rename.source);
      if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        PushBackIfNotTruncated(targets, msg->event.rename.destination.existing_file);
      } else if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackIfNotTruncated(targets, msg->event.rename.destination.new_path.dir,
                               msg->event.rename.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for rename event: %d. Ignoring destination.",
             msg->event.rename.destination_type);
      }
      break;

    case ES_EVENT_TYPE_AUTH_TRUNCATE:
      PushBackIfNotTruncated(targets, msg->event.truncate.target);
      break;

    case ES_EVENT_TYPE_AUTH_UNLINK:
      PushBackIfNotTruncated(targets, msg->event.unlink.target);
      break;

    default:
      [NSException
         raise:@"Unexpected event type"
        format:@"File Access Authorizer client does not handle event: %d", msg->event_type];
      exit(EXIT_FAILURE);
  }
}

bool ShouldMessageTTY(const std::shared_ptr<WatchItemPolicy> &policy, const Message &msg,
                      ProcessSet<std::pair<std::string, std::string>> &ttyMessageCache) {
  if (policy->silent_tty || !TTYWriter::CanWrite(msg->process)) {
    return false;
  }

  // ExistsOrSet returns `true` if the item existed. However we want to invert
  // this result as the return value for this function since we want to message
  // the TTY only when `ExistsOrSet` was a "set" operation, meaning it was the
  // first time this value was added.
  return !ttyMessageCache.ExistsOrSet(msg->process, ^std::pair<std::string, std::string>() {
    return {policy->version, policy->name};
  });
}

@interface SNTEndpointSecurityFileAccessAuthorizer ()
@property SNTConfigurator *configurator;
@property SNTDecisionCache *decisionCache;
@property bool isSubscribed;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizer {
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
  std::shared_ptr<Enricher> _enricher;
  std::shared_ptr<RateLimiter> _rateLimiter;
  SantaCache<SantaVnode, NSString *> _certHashCache;
  std::shared_ptr<TTYWriter> _ttyWriter;
  ProcessSet<std::pair<dev_t, ino_t>> _readsCache;
  ProcessSet<std::pair<std::string, std::string>> _ttyMessageCache;
  std::shared_ptr<Metrics> _metrics;
}

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<Metrics>)metrics
                       logger:(std::shared_ptr<santa::Logger>)logger
                   watchItems:(std::shared_ptr<WatchItems>)watchItems
                     enricher:(std::shared_ptr<santa::Enricher>)enricher
                decisionCache:(SNTDecisionCache *)decisionCache
                    ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:metrics
                    processor:santa::Processor::kFileAccessAuthorizer];
  if (self) {
    _watchItems = std::move(watchItems);
    _logger = std::move(logger);
    _enricher = std::move(enricher);
    _decisionCache = decisionCache;
    _ttyWriter = std::move(ttyWriter);
    _metrics = std::move(metrics);

    _configurator = [SNTConfigurator configurator];

    _rateLimiter =
      RateLimiter::Create(_metrics, santa::Processor::kFileAccessAuthorizer, kDefaultRateLimitQPS);

    SNTMetricBooleanGauge *famEnabled = [[SNTMetricSet sharedInstance]
      booleanGaugeWithName:@"/santa/fam_enabled"
                fieldNames:@[]
                  helpText:@"Whether or not the FAM client is enabled"];

    WEAKIFY(self);
    [[SNTMetricSet sharedInstance] registerCallback:^{
      STRONGIFY(self);
      [famEnabled set:self.isSubscribed forFieldValues:@[]];
    }];

    [self establishClientOrDie];

    [super enableTargetPathWatching];
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
                                          target:(const PathTarget &)target
                                         message:(const Message &)msg {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN:
      // If the policy is write-only, but the operation isn't a write action, it's allowed
      if (policy->allow_read_access && !(msg->event.open.fflag & kOpenFlagsIndicatingWrite)) {
        return FileAccessPolicyDecision::kAllowedReadAccess;
      }
      break;

    case ES_EVENT_TYPE_AUTH_CLONE:
      // If policy is write-only, readable targets are allowed (e.g. source file)
      if (policy->allow_read_access && target.isReadable) {
        return FileAccessPolicyDecision::kAllowedReadAccess;
      }
      break;

    case ES_EVENT_TYPE_AUTH_COPYFILE:
      // Note: Flags for the copyfile event represent the kernel view, not the usersapce
      // copyfile(3) implementation. This means if a `copyfile(3)` flag like `COPYFILE_MOVE`
      // is specified, it will come as a separate `unlink(2)` event, not a flag here.
      if (policy->allow_read_access && target.isReadable) {
        return FileAccessPolicyDecision::kAllowedReadAccess;
      }
      break;

    case ES_EVENT_TYPE_AUTH_CREATE:
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
    case ES_EVENT_TYPE_AUTH_LINK:
    case ES_EVENT_TYPE_AUTH_RENAME:
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
    case ES_EVENT_TYPE_AUTH_UNLINK:
      // These event types have no special case
      break;

    default:
      [NSException raise:@"Unexpected event type"
                  format:@"Received unexpected event type in the file access authorizer: %d",
                         msg->event_type];
      exit(EXIT_FAILURE);
  }

  return FileAccessPolicyDecision::kNoPolicy;
}

/// An An `es_process_t` must match all criteria within the given
/// WatchItemPolicy::Process to be considered a match.
- (bool)policyProcess:(const WatchItemPolicy::Process &)policyProc
     matchesESProcess:(const es_process_t *)esProc {
  // Note: Intentionally not checking `CS_VALID` here - this check must happen
  // outside of this method. This method is used to individually check each
  // configured process exception while the check for a valid code signature
  // is more broad and applies whether or not process exceptions exist.
  if (esProc->codesigning_flags & CS_SIGNED) {
    // Check whether or not the process is a platform binary if specified by the policy.
    if (policyProc.platform_binary.has_value() &&
        policyProc.platform_binary.value() != esProc->is_platform_binary) {
      return false;
    }

    // If the policy contains a team ID, check that the instigating process
    // also has a team ID and matches the policy.
    if (!policyProc.team_id.empty() &&
        (!esProc->team_id.data || (policyProc.team_id != esProc->team_id.data))) {
      // We expected a team ID to match against, but the process didn't have one.
      return false;
    }

    // If the policy contains a signing ID, check that the instigating process
    // also has a signing ID and matches the policy.
    if (!policyProc.signing_id.empty() &&
        (!esProc->signing_id.data || (policyProc.signing_id != esProc->signing_id.data))) {
      return false;
    }

    // Check if the instigating process has an allowed CDHash
    if (policyProc.cdhash.size() == CS_CDHASH_LEN &&
        std::memcmp(policyProc.cdhash.data(), esProc->cdhash, CS_CDHASH_LEN) != 0) {
      return false;
    }

    // Check if the instigating process has an allowed certificate hash
    if (!policyProc.certificate_sha256.empty()) {
      NSString *result = [self getCertificateHash:esProc->executable];
      if (!result || policyProc.certificate_sha256 != [result UTF8String]) {
        return false;
      }
    }
  } else {
    // If the process isn't signed, ensure the policy doesn't contain any
    // attributes that require a signature
    if (!policyProc.team_id.empty() || !policyProc.signing_id.empty() ||
        policyProc.cdhash.size() == CS_CDHASH_LEN || !policyProc.certificate_sha256.empty()) {
      return false;
    }
  }

  // Check if the instigating process path opening the file is allowed
  if (policyProc.binary_path.length() > 0 &&
      policyProc.binary_path != esProc->executable->path.data) {
    return false;
  }

  return true;
}

// The operation is allowed when:
//   - No policy exists
//   - The policy is write-only, but the operation is read-only
//   - The operation was instigated by an allowed process
//   - If the instigating process is signed, the codesignature is valid
// Otherwise the operation is denied.
- (FileAccessPolicyDecision)applyPolicy:
                              (std::optional<std::shared_ptr<WatchItemPolicy>>)optionalPolicy
                              forTarget:(const PathTarget &)target
                              toMessage:(const Message &)msg {
  // If no policy exists, everything is allowed
  if (!optionalPolicy.has_value()) {
    return FileAccessPolicyDecision::kNoPolicy;
  }

  // If the process is signed but has an invalid signature, it is denied
  if (((msg->process->codesigning_flags & (CS_SIGNED | CS_VALID)) == CS_SIGNED) &&
      [self.configurator enableBadSignatureProtection]) {
    // TODO(mlw): Think about how to make stronger guarantees here to handle
    // programs becoming invalid after first being granted access. Maybe we
    // should only allow things that have hardened runtime flags set?
    return FileAccessPolicyDecision::kDeniedInvalidSignature;
  }

  std::shared_ptr<WatchItemPolicy> policy = optionalPolicy.value();

  // If policy allows reading, add target to the cache
  if (policy->allow_read_access && target.devnoIno.has_value()) {
    self->_readsCache.Set(msg->process, ^{
      return *target.devnoIno;
    });
  }

  // Check if this action contains any special case that would produce
  // an immediate result.
  FileAccessPolicyDecision specialCase = [self specialCaseForPolicy:policy
                                                             target:target
                                                            message:msg];
  if (specialCase != FileAccessPolicyDecision::kNoPolicy) {
    return specialCase;
  }

  FileAccessPolicyDecision decision = FileAccessPolicyDecision::kDenied;

  for (const WatchItemPolicy::Process &process : policy->processes) {
    if ([self policyProcess:process matchesESProcess:msg->process]) {
      decision = FileAccessPolicyDecision::kAllowed;
      break;
    }
  }

  // If the `invert_process_exceptions` option is set, the decision should be
  // inverted from allowed to denied or vice versa. Note that this inversion
  // must be made prior to checking the policy's audit-only flag.
  if (policy->invert_process_exceptions) {
    if (decision == FileAccessPolicyDecision::kAllowed) {
      decision = FileAccessPolicyDecision::kDenied;
    } else {
      decision = FileAccessPolicyDecision::kAllowed;
    }
  }

  if (decision == FileAccessPolicyDecision::kDenied && policy->audit_only) {
    decision = FileAccessPolicyDecision::kAllowedAuditOnly;
  }

  return decision;
}

- (FileAccessPolicyDecision)handleMessage:(const Message &)msg
                                   target:(const PathTarget &)target
                                   policy:
                                     (std::optional<std::shared_ptr<WatchItemPolicy>>)optionalPolicy
                            policyVersion:(const std::string &)policyVersion
                           overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  FileAccessPolicyDecision policyDecision = ApplyOverrideToDecision(
    [self applyPolicy:optionalPolicy forTarget:target toMessage:msg], overrideAction);

  // Note: If ShouldLogDecision, it shouldn't be possible for optionalPolicy
  // to not have a value. Performing the check just in case to prevent a crash.
  if (ShouldLogDecision(policyDecision) && optionalPolicy.has_value()) {
    std::shared_ptr<WatchItemPolicy> policy = optionalPolicy.value();
    RateLimiter::Decision decision = _rateLimiter->Decide(msg->mach_time);

    self->_metrics->SetFileAccessEventMetrics(policyVersion, policy->name,
                                              (decision == RateLimiter::Decision::kAllowed)
                                                ? FileAccessMetricStatus::kOK
                                                : FileAccessMetricStatus::kBlockedUser,
                                              msg->event_type, policyDecision);

    if (decision == RateLimiter::Decision::kAllowed) {
      std::string policyNameCopy = policy->name;
      std::string policyVersionCopy = policyVersion;
      std::string targetPathCopy = target.path;

      [self asynchronouslyProcess:msg
                          handler:^(Message &&esMsg) {
                            self->_logger->LogFileAccess(
                              policyVersionCopy, policyNameCopy, esMsg,
                              self->_enricher->Enrich(*esMsg->process, EnrichOptions::kLocalOnly),
                              targetPathCopy, policyDecision);
                          }];
    }

    // Notify users on block decisions
    if (ShouldNotifyUserDecision(policyDecision) &&
        (!policy->silent || (!policy->silent_tty && TTYWriter::CanWrite(msg->process)))) {
      SNTCachedDecision *cd =
        [self.decisionCache cachedDecisionForFile:msg->process->executable->stat];

      SNTFileAccessEvent *event = [[SNTFileAccessEvent alloc] init];

      event.accessedPath = StringToNSString(target.path);
      event.ruleVersion = StringToNSString(policy->version);
      event.ruleName = StringToNSString(policy->name);

      event.fileSHA256 = cd.sha256 ?: @"<unknown sha>";
      event.filePath = StringToNSString(msg->process->executable->path.data);
      event.teamID = cd.teamID ?: @"<unknown team id>";
      event.teamID = cd.signingID ?: @"<unknown signing id>";
      event.pid = @(audit_token_to_pid(msg->process->audit_token));
      event.ppid = @(audit_token_to_pid(msg->process->parent_audit_token));
      event.parentName = StringToNSString(msg.ParentProcessName());
      event.signingChain = cd.certChain;

      std::pair<NSString *, NSString *> linkInfo = self->_watchItems->EventDetailLinkInfo(policy);

      if (!policy->silent && self.fileAccessBlockCallback) {
        self.fileAccessBlockCallback(event, OptionalStringToNSString(policy->custom_message),
                                     linkInfo.first, linkInfo.second);
      }

      if (ShouldMessageTTY(policy, msg, self->_ttyMessageCache)) {
        NSAttributedString *attrStr =
          [SNTBlockMessage attributedBlockMessageForFileAccessEvent:event
                                                      customMessage:OptionalStringToNSString(
                                                                      policy->custom_message)];

        NSMutableString *blockMsg = [NSMutableString stringWithCapacity:1024];
        // Escape sequences `\033[1m` and `\033[0m` begin/end bold lettering
        [blockMsg appendFormat:@"\n\033[1mSanta\033[0m\n\n%@\n\n", attrStr.string];
        [blockMsg appendFormat:@"\033[1mAccessed Path:\033[0m %@\n"
                               @"\033[1mRule Version: \033[0m %@\n"
                               @"\033[1mRule Name:    \033[0m %@\n"
                               @"\n"
                               @"\033[1mProcess Path: \033[0m %@\n"
                               @"\033[1mIdentifier:   \033[0m %@\n"
                               @"\033[1mParent:       \033[0m %@\n\n",
                               event.accessedPath, event.ruleVersion, event.ruleName,
                               event.filePath, event.fileSHA256, event.parentName];

        NSURL *detailURL = [SNTBlockMessage eventDetailURLForFileAccessEvent:event
                                                                   customURL:linkInfo.first];
        if (detailURL) {
          [blockMsg appendFormat:@"More info:\n%@\n\n", detailURL.absoluteString];
        }

        self->_ttyWriter->Write(msg->process, blockMsg);
      }
    }
  }

  return policyDecision;
}

- (void)processMessage:(const Message &)msg
        overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  std::vector<PathTarget> targets;
  targets.reserve(2);
  PopulatePathTargets(msg, targets);

  // Extract the paths from the vector of PathTargets in order to lookup policies
  // Note: There should only ever be 1 or 2 items in the vector
  std::vector<std::string_view> paths;
  paths.reserve(2);
  for (const PathTarget &target : targets) {
    paths.push_back(std::string_view(target.path));
  }

  WatchItems::VersionAndPolicies versionAndPolicies = self->_watchItems->FindPolciesForPaths(paths);

  es_auth_result_t policyResult = ES_AUTH_RESULT_ALLOW;
  bool allow_read_access = false;

  for (size_t i = 0; i < targets.size(); i++) {
    FileAccessPolicyDecision curDecision = [self handleMessage:msg
                                                        target:targets[i]
                                                        policy:versionAndPolicies.second[i]
                                                 policyVersion:versionAndPolicies.first
                                                overrideAction:overrideAction];

    policyResult =
      CombinePolicyResults(policyResult, FileAccessPolicyDecisionToESAuthResult(curDecision));

    // If the overall policy result is deny, then reset allow_read_access.
    // Otherwise if the current decision would allow read access, set the flag.
    if (policyResult == ES_AUTH_RESULT_DENY) {
      allow_read_access = false;
    } else if (curDecision == FileAccessPolicyDecision::kAllowedReadAccess) {
      allow_read_access = true;
    }
  }

  // IMPORTANT: A response is only cacheable if the policy result was explicitly
  // allowed. An "allow read access" result must not be cached to ensure a future
  // non-read accesss can be evaluated. Similarly, denied results must never be
  // cached so access attempts can be logged.
  [self respondToMessage:msg
          withAuthResult:policyResult
               cacheable:(policyResult == ES_AUTH_RESULT_ALLOW && !allow_read_access)];
}

- (void)handleMessage:(santa::Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  SNTOverrideFileAccessAction overrideAction = [self.configurator overrideFileAccessAction];

  // If the override action is set to Disable, return immediately.
  if (overrideAction == SNTOverrideFileAccessActionDiable) {
    if (esMsg->action_type == ES_ACTION_TYPE_AUTH) {
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
    }
    return;
  }

  if (esMsg->event_type == ES_EVENT_TYPE_AUTH_OPEN &&
      !(esMsg->event.open.fflag & kOpenFlagsIndicatingWrite)) {
    if (self->_readsCache.Exists(esMsg->process, ^std::pair<pid_t, pid_t> {
          return std::pair<dev_t, ino_t>{esMsg->event.open.file->stat.st_dev,
                                         esMsg->event.open.file->stat.st_ino};
        })) {
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
      return;
    }
  } else if (esMsg->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
    // On process exit, remove the cache entry
    self->_readsCache.Remove(esMsg->process);
    self->_ttyMessageCache.Remove(esMsg->process);
    return;
  }

  [self processMessage:std::move(esMsg)
               handler:^(const Message &msg) {
                 [self processMessage:msg overrideAction:overrideAction];
                 recordEventMetrics(EventDisposition::kProcessed);
               }];
}

- (void)enable {
  std::set<es_event_type_t> events = {
    ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
    ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
    ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  if (!self.isSubscribed) {
    if ([super subscribe:events]) {
      self.isSubscribed = true;
    }
  }

  // Always clear cache to ensure operations that were previously allowed are re-evaluated.
  [super clearCache];
}

- (void)disable {
  if (self.isSubscribed) {
    if ([super unsubscribeAll]) {
      self.isSubscribed = false;
    }
    [super unmuteAllTargetPaths];
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

  self->_readsCache.Clear();
}

@end
