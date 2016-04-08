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

#import "SNTRuleTable.h"

#import "MOLCertificate.h"
#import "MOLCodesignChecker.h"
#import "SNTConfigurator.h"
#import "SNTLogging.h"
#import "SNTRule.h"

@interface SNTRuleTable ()
@property NSString *santadCertSHA;
@property NSString *launchdCertSHA;
@end

@implementation SNTRuleTable

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  // Lock this database from other processes
  [db executeQuery:@"PRAGMA locking_mode = EXCLUSIVE;"];

  // Save hashes of the signing certs for launchd and santad
  self.santadCertSHA = [[[[MOLCodesignChecker alloc] initWithSelf] leafCertificate] SHA256];
  self.launchdCertSHA = [[[[MOLCodesignChecker alloc] initWithPID:1] leafCertificate] SHA256];

  uint32_t newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'rules' ("
                      @"'shasum' TEXT NOT NULL, "
                      @"'state' INTEGER NOT NULL, "
                      @"'type' INTEGER NOT NULL, "
                      @"'custommsg' TEXT"
                      @")"];

    [db executeUpdate:@"CREATE VIEW binrules AS SELECT * FROM rules WHERE type=1"];
    [db executeUpdate:@"CREATE VIEW certrules AS SELECT * FROM rules WHERE type=2"];

    [db executeUpdate:@"CREATE UNIQUE INDEX rulesunique ON rules (shasum, type)"];

    // Insert the codesigning certs for the running santad and launchd into the initial database.
    // This helps prevent accidentally denying critical system components while the database
    // is empty. This 'initial database' will then be cleared on the first successful sync.
    [db executeUpdate:@"INSERT INTO rules (shasum, state, type) VALUES (?, ?, ?)",
                      self.santadCertSHA, @(RULESTATE_WHITELIST), @(RULETYPE_CERT)];
    [db executeUpdate:@"INSERT INTO rules (shasum, state, type) VALUES (?, ?, ?)",
                      self.launchdCertSHA, @(RULESTATE_WHITELIST), @(RULETYPE_CERT)];

    newVersion = 1;

    [[SNTConfigurator configurator] setSyncCleanRequired:YES];
  }

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

- (NSUInteger)binaryRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM binrules"];
  }];
  return count;
}

- (NSUInteger)certificateRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM certrules"];
  }];
  return count;
}

- (SNTRule *)ruleFromResultSet:(FMResultSet *)rs {
  SNTRule *rule = [[SNTRule alloc] init];

  rule.shasum = [rs stringForColumn:@"shasum"];
  rule.type = [rs intForColumn:@"type"];
  rule.state = [rs intForColumn:@"state"];
  rule.customMsg = [rs stringForColumn:@"custommsg"];

  return rule;
}

- (SNTRule *)certificateRuleForSHA256:(NSString *)SHA256 {
  __block SNTRule *rule;

  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM certrules WHERE shasum=? LIMIT 1", SHA256];
    if ([rs next]) {
      rule = [self ruleFromResultSet:rs];
    }
    [rs close];
  }];

  return rule;
}

- (SNTRule *)binaryRuleForSHA256:(NSString *)SHA256 {
  __block SNTRule *rule;

  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM binrules WHERE shasum=? LIMIT 1", SHA256];
    if ([rs next]) {
      rule = [self ruleFromResultSet:rs];
    }
    [rs close];
  }];

  return rule;
}

#pragma mark Adding

- (BOOL)addRules:(NSArray *)rules cleanSlate:(BOOL)cleanSlate {
  if (!rules || rules.count < 1) {
    LOGE(@"Received request to add rules with nil/empty array.");
    return NO;
  }

  __block BOOL failed = NO;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    // Protect rules for santad/launchd certificates.
    NSPredicate *p = [NSPredicate predicateWithFormat:
                                      @"(SELF.shasum = %@ OR SELF.shasum = %@) AND SELF.type = %d",
                                      self.santadCertSHA, self.launchdCertSHA, RULETYPE_CERT];
    NSArray *requiredHashes = [rules filteredArrayUsingPredicate:p];
    p = [NSPredicate predicateWithFormat:@"SELF.state == %d", RULESTATE_WHITELIST];
    NSArray *requiredHashesWhitelist = [requiredHashes filteredArrayUsingPredicate:p];
    if ((cleanSlate && requiredHashesWhitelist.count != 2) ||
        (requiredHashes.count != requiredHashesWhitelist.count)) {
      LOGE(@"Received request to remove whitelist for launchd/santad certificates.");
      *rollback = failed = YES;
      return;
    }

    if (cleanSlate) {
      [db executeUpdate:@"DELETE FROM rules"];
    }

    for (SNTRule *rule in rules) {
      if (![rule isKindOfClass:[SNTRule class]] || rule.shasum.length == 0 ||
          rule.state == RULESTATE_UNKNOWN || rule.type == RULETYPE_UNKNOWN) {
        *rollback = failed = YES;
        return;
      }

      if (rule.state == RULESTATE_REMOVE) {
        if (![db executeUpdate:@"DELETE FROM rules WHERE shasum=? AND type=?",
                               rule.shasum, @(rule.type)]) {
          *rollback = failed = YES;
          return;
        }
      } else {
        if (![db executeUpdate:@"INSERT OR REPLACE INTO rules "
                               @"(shasum, state, type, custommsg) "
                               @"VALUES (?, ?, ?, ?);",
                               rule.shasum, @(rule.state), @(rule.type), rule.customMsg]) {
          *rollback = failed = YES;
          return;
        }
      }
    }
  }];

  return !failed;
}

@end
