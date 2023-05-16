/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/santad/DataLayer/SNTRuleTable.h"

#import <EndpointSecurity/EndpointSecurity.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

#import "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"

static const uint32_t kRuleTableCurrentVersion = 4;

// TODO(nguyenphillip): this should be configurable.
// How many rules must be in database before we start trying to remove transitive rules.
static const NSUInteger kTransitiveRuleCullingThreshold = 500000;
// Consider transitive rules out of date if they haven't been used in six months.
static const NSUInteger kTransitiveRuleExpirationSeconds = 6 * 30 * 24 * 3600;

static void addPathsFromDefaultMuteSet(NSMutableSet *criticalPaths) API_AVAILABLE(macos(12.0)) {
  // Note: This function uses API introduced in macOS 12, but we want to continue to support
  // building in older environments. API Availability checks do not help for this use case,
  // instead we use the following preprocessor macros to conditionally compile these API. The
  // drawback here is that if a pre-macOS 12 SDK is used to build Santa and it is then deployed
  // on macOS 12 or later, the dynamic mute set will not be computed.
#if HAVE_MACOS_12
  // Create a temporary ES client in order to grab the default set of muted paths.
  // TODO(mlw): Reorganize this code so that a temporary ES client doesn't need to be created
  es_client_t *client = NULL;
  es_new_client_result_t ret = es_new_client(&client, ^(es_client_t *c, const es_message_t *m){
                                               // noop
                                             });

  if (ret != ES_NEW_CLIENT_RESULT_SUCCESS) {
    // Creating the client failed, so we cannot grab the current default mute set.
    LOGE(@"Failed to create client to grab default muted paths");
    return;
  }

  es_muted_paths_t *mps = NULL;
  if (es_muted_paths_events(client, &mps) != ES_RETURN_SUCCESS) {
    LOGE(@"Failed to obtain list of default muted paths.");
    es_delete_client(client);
    return;
  }

  for (size_t i = 0; i < mps->count; i++) {
    // Only add literal paths, prefix paths would require recursive directory search
    if (mps->paths[i].type == ES_MUTE_PATH_TYPE_LITERAL) {
      [criticalPaths addObject:@(mps->paths[i].path.data)];
    }
  }

  es_release_muted_paths(mps);
  es_delete_client(client);
#endif
}

@interface SNTRuleTable ()
@property MOLCodesignChecker *santadCSInfo;
@property MOLCodesignChecker *launchdCSInfo;
@property NSDate *lastTransitiveRuleCulling;
@property NSDictionary *criticalSystemBinaries;
@property(readonly) NSArray *criticalSystemBinaryPaths;
@end

@implementation SNTRuleTable

//  ES on Monterey now has a “default mute set” of paths that are automatically applied to each ES
//  client. This mute set contains most (not all) AUTH event types for some paths that were deemed
//  “system critical”.
+ (NSArray *)criticalSystemBinaryPaths {
  static dispatch_once_t onceToken;
  static NSArray *criticalPaths = nil;
  dispatch_once(&onceToken, ^{
    // These paths have previously existed in the ES default mute set. They are hardcoded
    // here in case grabbing the current default mute set fails, or if Santa is running on
    // an OS that did not yet support this feature.
    NSSet *fallbackDefaultMuteSet = [[NSSet alloc] initWithArray:@[
      @"/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer",
      @"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
      @"/System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/tccd",
      @"/usr/sbin/cfprefsd",
      @"/usr/sbin/securityd",
      @"/usr/libexec/opendirectoryd",
      @"/usr/libexec/sandboxd",
      @"/usr/libexec/syspolicyd",
      @"/usr/libexec/runningboardd",
      @"/usr/libexec/amfid",
      @"/usr/libexec/watchdogd",
    ]];

    // This is a Santa-curated list of paths to check on startup. This list will be merged
    // with the set of default muted paths from ES.

    NSSet *santaDefinedCriticalPaths = [NSSet setWithArray:@[
      @"/usr/libexec/trustd",
      @"/usr/lib/dyld",
      @"/usr/libexec/xpcproxy",
      @"/usr/sbin/ocspd",
      @"/Applications/Santa.app/Contents/MacOS/Santa",
      @"/Applications/Santa.app/Contents/MacOS/santactl",
      @"/Applications/Santa.app/Contents/MacOS/santabundleservice",
      @"/Applications/Santa.app/Contents/MacOS/santametricservice",
      @"/Applications/Santa.app/Contents/MacOS/santasyncservice",
    ]];

    // Combine the fallback default mute set and Santa-curated set
    NSMutableSet *superSet = [NSMutableSet setWithSet:fallbackDefaultMuteSet];
    [superSet unionSet:santaDefinedCriticalPaths];

    if (@available(macOS 12.0, *)) {
      // Attempt to add the real default mute set
      addPathsFromDefaultMuteSet(superSet);
    }

    criticalPaths = [superSet allObjects];
  });

  return criticalPaths;
}

- (void)setupSystemCriticalBinaries {
  NSMutableDictionary *bins = [NSMutableDictionary dictionary];
  for (NSString *path in [SNTRuleTable criticalSystemBinaryPaths]) {
    SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:path];
    if (!binInfo.SHA256) {
      // If there isn't a hash, no need to compute the other info here.
      // Just continue on to the next binary.
      LOGW(@"Unable to compute hash for critical system binary %@.", path);
      continue;
    }
    MOLCodesignChecker *csInfo = [binInfo codesignCheckerWithError:NULL];

    // Make sure the critical system binary is signed by the same chain as launchd/self
    BOOL systemBin = NO;
    if ([csInfo signingInformationMatches:self.launchdCSInfo]) {
      systemBin = YES;
    } else if (![csInfo signingInformationMatches:self.santadCSInfo]) {
      LOGW(@"Unable to validate critical system binary %@. "
           @"pid 1: %@, santad: %@ and %@: %@ do not match.",
           path, self.launchdCSInfo.leafCertificate, self.santadCSInfo.leafCertificate, path,
           csInfo.leafCertificate);
      continue;
    }

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];

    cd.decision = SNTEventStateAllowBinary;
    cd.decisionExtra = systemBin ? @"critical system binary" : @"santa binary";
    cd.sha256 = binInfo.SHA256;

    // Not needed, but nice for logging.
    cd.certSHA256 = csInfo.leafCertificate.SHA256;
    cd.certCommonName = csInfo.leafCertificate.commonName;

    bins[binInfo.SHA256] = cd;
  }
  self.criticalSystemBinaries = bins;
}

- (uint32_t)currentSupportedVersion {
  return kRuleTableCurrentVersion;
}

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  // Lock this database from other processes
  [[db executeQuery:@"PRAGMA locking_mode = EXCLUSIVE;"] close];

  uint32_t newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'rules' ("
                      @"'shasum' TEXT NOT NULL, "
                      @"'state' INTEGER NOT NULL, "
                      @"'type' INTEGER NOT NULL, "
                      @"'custommsg' TEXT"
                      @")"];
    [db executeUpdate:@"CREATE UNIQUE INDEX rulesunique ON rules (shasum, type)"];

    [[SNTConfigurator configurator] setSyncCleanRequired:YES];

    newVersion = 1;
  }

  if (version < 2) {
    [db executeUpdate:@"DROP VIEW IF EXISTS binrules"];
    [db executeUpdate:@"DROP VIEW IF EXISTS certrules"];
    newVersion = 2;
  }

  if (version < 3) {
    // Add timestamp column for tracking age of transitive rules.
    [db executeUpdate:@"ALTER TABLE 'rules' ADD 'timestamp' INTEGER"];
    newVersion = 3;
  }

  if (version < 4) {
    // Rename `shasum` column to `identifier`.
    [db executeUpdate:@"ALTER TABLE 'rules' RENAME COLUMN 'shasum' TO 'identifier'"];
    newVersion = 4;
  }

  if (version < 5) {
    // Migrate SNTRuleType enum values
    [db executeUpdate:@"UPDATE rules SET type = 1000 WHERE type = 1"];
    [db executeUpdate:@"UPDATE rules SET type = 3000 WHERE type = 2"];
    [db executeUpdate:@"UPDATE rules SET type = 4000 WHERE type = 3"];
    [db executeUpdate:@"UPDATE rules SET type = 2000 WHERE type = 4"];

    newVersion = 5;
  }

  // Save signing info for launchd and santad. Used to ensure they are always allowed.
  self.santadCSInfo = [[MOLCodesignChecker alloc] initWithSelf];
  self.launchdCSInfo = [[MOLCodesignChecker alloc] initWithPID:1];

  // Setup critical system binaries
  [self setupSystemCriticalBinaries];

  return newVersion;
}

#pragma mark Entry Counts

- (NSUInteger)ruleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules"];
  }];
  return count;
}

- (NSUInteger)ruleCountForRuleType:(SNTRuleType)ruleType {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE type=?", @(ruleType)];
  }];
  return count;
}

- (NSUInteger)binaryRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeBinary];
}

- (NSUInteger)certificateRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeCertificate];
}

- (NSUInteger)compilerRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count =
      [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE state=?", @(SNTRuleStateAllowCompiler)];
  }];
  return count;
}

- (NSUInteger)transitiveRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count =
      [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE state=?", @(SNTRuleStateAllowTransitive)];
  }];
  return count;
}

- (NSUInteger)teamIDRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeTeamID];
}

- (NSUInteger)signingIDRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeSigningID];
}

- (SNTRule *)ruleFromResultSet:(FMResultSet *)rs {
  return [[SNTRule alloc] initWithIdentifier:[rs stringForColumn:@"identifier"]
                                       state:[rs intForColumn:@"state"]
                                        type:[rs intForColumn:@"type"]
                                   customMsg:[rs stringForColumn:@"custommsg"]
                                   timestamp:[rs intForColumn:@"timestamp"]];
}

- (SNTRule *)ruleForBinarySHA256:(NSString *)binarySHA256
                       signingID:(NSString *)signingID
               certificateSHA256:(NSString *)certificateSHA256
                          teamID:(NSString *)teamID {
  __block SNTRule *rule;

  // Look for a static rule that matches.
  NSDictionary *staticRules = [[SNTConfigurator configurator] staticRules];
  if (staticRules.count) {
    // IMPORTANT: The order static rules are checked here should be the same
    // order as given by the SQL query for the rules database.
    rule = staticRules[binarySHA256];
    if (rule.type == SNTRuleTypeBinary) {
      return rule;
    }

    rule = staticRules[signingID];
    if (rule.type == SNTRuleTypeSigningID) {
      return rule;
    }

    rule = staticRules[certificateSHA256];
    if (rule.type == SNTRuleTypeCertificate) {
      return rule;
    }

    rule = staticRules[teamID];
    if (rule.type == SNTRuleTypeTeamID) {
      return rule;
    }
  }

  // Now query the database.
  //
  // NOTE: This code is written with the intention that the binary rule is searched for first
  // as Santa is designed to go with the most-specific rule possible.
  //
  // The intended order of precedence is Binaries > Signing IDs > Certificates > Team IDs.
  //
  // As such the query should have "ORDER BY type DESC" before the LIMIT, to ensure that is the
  // case. However, in all tested versions of SQLite that ORDER BY clause is unnecessary: the query
  // is performed 'as written' by doing separate lookups in the index and the later lookups are if
  // the first returns a result. That behavior can be checked here: http://sqlfiddle.com/#!5/cdc42/1
  //
  // Adding the ORDER BY clause slows down this query, particularly in a database where
  // the number of binary rules outweighs the number of certificate rules because:
  //       a) now it can't avoid the certificate rule lookup when a binary rule is found
  //       b) after fetching the results it now has to sort even if there's just 1 row
  //
  // There is a test for this in SNTRuleTableTests in case SQLite behavior changes in the future.
  //
  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM rules WHERE "
                                       @"   (identifier=? and type=1000) "
                                       @"OR (identifier=? AND type=2000) "
                                       @"OR (identifier=? AND type=3000) "
                                       @"OR (identifier=? AND type=4000) LIMIT 1",
                                       binarySHA256, signingID, certificateSHA256, teamID];
    if ([rs next]) {
      rule = [self ruleFromResultSet:rs];
    }
    [rs close];
  }];

  // Allow binaries signed by the "Software Signing" cert used to sign launchd
  // if no existing rule has matched.
  if (!rule && [certificateSHA256 isEqual:self.launchdCSInfo.leafCertificate.SHA256]) {
    rule = [[SNTRule alloc] initWithIdentifier:certificateSHA256
                                         state:SNTRuleStateAllow
                                          type:SNTRuleTypeCertificate
                                     customMsg:nil
                                     timestamp:0];
  }

  return rule;
}

#pragma mark Adding

- (BOOL)addRules:(NSArray *)rules
      cleanSlate:(BOOL)cleanSlate
           error:(NSError *__autoreleasing *)error {
  if (!rules || rules.count < 1) {
    [self fillError:error code:SNTRuleTableErrorEmptyRuleArray message:nil];
    return NO;
  }

  __block BOOL failed = NO;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    if (cleanSlate) {
      [db executeUpdate:@"DELETE FROM rules"];
    }

    for (SNTRule *rule in rules) {
      if (![rule isKindOfClass:[SNTRule class]] || rule.identifier.length == 0 ||
          rule.state == SNTRuleStateUnknown || rule.type == SNTRuleTypeUnknown) {
        [self fillError:error code:SNTRuleTableErrorInvalidRule message:rule.description];
        *rollback = failed = YES;
        return;
      }

      if (rule.state == SNTRuleStateRemove) {
        if (![db executeUpdate:@"DELETE FROM rules WHERE identifier=? AND type=?", rule.identifier,
                               @(rule.type)]) {
          [self fillError:error code:SNTRuleTableErrorRemoveFailed message:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      } else {
        if (![db executeUpdate:@"INSERT OR REPLACE INTO rules "
                               @"(identifier, state, type, custommsg, timestamp) "
                               @"VALUES (?, ?, ?, ?, ?);",
                               rule.identifier, @(rule.state), @(rule.type), rule.customMsg,
                               @(rule.timestamp)]) {
          [self fillError:error
                     code:SNTRuleTableErrorInsertOrReplaceFailed
                  message:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      }
    }
  }];

  return !failed;
}

- (BOOL)addedRulesShouldFlushDecisionCache:(NSArray *)rules {
  // Check for non-plain-allowlist rules first before querying the database.
  for (SNTRule *rule in rules) {
    if (rule.state != SNTRuleStateAllow) return YES;
  }

  // If still here, then all rules in the array are allowlist rules.  So now we look for allowlist
  // rules where there is a previously existing allowlist compiler rule for the same identifier.
  // If so we find such a rule, then cache should be flushed.
  __block BOOL flushDecisionCache = NO;
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    for (SNTRule *rule in rules) {
      // Allowlist certificate rules are ignored
      if (rule.type == SNTRuleTypeCertificate) continue;

      if ([db longForQuery:
                @"SELECT COUNT(*) FROM rules WHERE identifier=? AND type=? AND state=? LIMIT 1",
                rule.identifier, @(SNTRuleTypeBinary), @(SNTRuleStateAllowCompiler)] > 0) {
        flushDecisionCache = YES;
        break;
      }
    }
  }];

  return flushDecisionCache;
}

// Updates the timestamp to current time for the given rule.
- (void)resetTimestampForRule:(SNTRule *)rule {
  if (!rule) return;
  [rule resetTimestamp];
  [self inDatabase:^(FMDatabase *db) {
    if (![db executeUpdate:@"UPDATE rules SET timestamp=? WHERE identifier=? AND type=?",
                           @(rule.timestamp), rule.identifier, @(rule.type)]) {
      LOGE(@"Could not update timestamp for rule with sha256=%@", rule.identifier);
    }
  }];
}

- (void)removeOutdatedTransitiveRules {
  // Don't attempt to remove transitive rules unless it's been at least an hour since the
  // last time we tried to remove them.
  if (self.lastTransitiveRuleCulling &&
      -[self.lastTransitiveRuleCulling timeIntervalSinceNow] < 3600)
    return;

  // Don't bother removing rules unless rule database is large.
  if ([self ruleCount] < kTransitiveRuleCullingThreshold) return;
  // Determine what timestamp qualifies as outdated.
  NSUInteger outdatedTimestamp =
    [[NSDate date] timeIntervalSinceReferenceDate] - kTransitiveRuleExpirationSeconds;

  [self inDatabase:^(FMDatabase *db) {
    if (![db executeUpdate:@"DELETE FROM rules WHERE state=? AND timestamp < ?",
                           @(SNTRuleStateAllowTransitive), @(outdatedTimestamp)]) {
      LOGE(@"Could not remove outdated transitive rules");
    }
  }];

  self.lastTransitiveRuleCulling = [NSDate date];
}

//  Helper to create an NSError where necessary.
//  The return value is irrelevant but the static analyzer complains if it's not a BOOL.
- (BOOL)fillError:(NSError **)error code:(SNTRuleTableError)code message:(NSString *)message {
  if (!error) return NO;

  NSMutableDictionary *d = [NSMutableDictionary dictionary];
  switch (code) {
    case SNTRuleTableErrorEmptyRuleArray: d[NSLocalizedDescriptionKey] = @"Empty rule array"; break;
    case SNTRuleTableErrorInvalidRule:
      d[NSLocalizedDescriptionKey] =
        [NSString stringWithFormat:@"Rule array contained invalid entry: %@", message];
      break;
    case SNTRuleTableErrorInsertOrReplaceFailed:
      d[NSLocalizedDescriptionKey] = @"A database error occurred while inserting/replacing a rule";
      break;
    case SNTRuleTableErrorRemoveFailed:
      d[NSLocalizedDescriptionKey] = @"A database error occurred while deleting a rule";
      break;
  }

  if (message) d[NSLocalizedFailureReasonErrorKey] = message;

  *error = [NSError errorWithDomain:@"com.google.santad.ruletable" code:code userInfo:d];
  return YES;
}

@end
