/// Copyright 2014 Google Inc. All rights reserved.
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

#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTNotificationMessage.h"
#import "SNTRule.h"

@implementation SNTRuleTable

- (int)initializeDatabase:(FMDatabase *)db fromVersion:(int)version {
  int newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'rules' ("
        @"'sha1' TEXT NOT NULL, "
        @"'state' INTEGER NOT NULL, "
        @"'type' INTEGER NOT NULL, "
        @"'customMsg' TEXT"
        @")"];

    [db executeUpdate:@"CREATE VIEW binrules AS SELECT * FROM rules WHERE type=1"];
    [db executeUpdate:@"CREATE VIEW certrules AS SELECT * FROM rules WHERE type=2"];

    [db executeUpdate:@"CREATE UNIQUE INDEX rulesunique ON rules (sha1, type)"];

    // Insert the codesigning certs for the running santad and launchd into the initial database.
    // This helps prevent accidentally denying critical system components while the database
    // is empty. This 'initial database' will then be cleared on the first successful sync.
    NSString *santadSHA = [[[[SNTCodesignChecker alloc] initWithSelf] leafCertificate] SHA1];
    NSString *launchdSHA = [[[[SNTCodesignChecker alloc] initWithPID:1] leafCertificate] SHA1];
    [db executeUpdate:@"INSERT INTO rules (sha1, state, type) VALUES (?, ?, ?)",
        santadSHA, @(RULESTATE_WHITELIST), @(RULETYPE_CERT)];
    [db executeUpdate:@"INSERT INTO rules (sha1, state, type) VALUES (?, ?, ?)",
        launchdSHA, @(RULESTATE_WHITELIST), @(RULETYPE_CERT)];

    newVersion = 1;
  }

  return newVersion;
}

#pragma mark Entry Counts

- (long)ruleCount {
  __block long count = 0;
  [self inDatabase:^(FMDatabase *db) {
      count = [db longForQuery:@"SELECT COUNT(*) FROM rules"];
  }];
  return count;
}

- (long)binaryRuleCount {
  __block long count = 0;
  [self inDatabase:^(FMDatabase *db) {
      count = [db longForQuery:@"SELECT COUNT(*) FROM binrules"];
  }];
  return count;
}

- (long)certificateRuleCount {
  __block long count = 0;
  [self inDatabase:^(FMDatabase *db) {
      count = [db longForQuery:@"SELECT COUNT(*) FROM certrules"];
  }];
  return count;
}

- (SNTRule *)ruleFromResultSet:(FMResultSet *)rs {
  SNTRule *rule = [[SNTRule alloc] init];

  rule.SHA1 = [rs stringForColumn:@"sha1"];
  rule.type = [rs intForColumn:@"type"];
  rule.state = [rs intForColumn:@"state"];
  rule.customMsg = [rs stringForColumn:@"customMsg"];

  return rule;
}

- (SNTRule *)certificateRuleForSHA1:(NSString *)SHA1 {
  __block SNTRule *rule;

  [self inDatabase:^(FMDatabase *db) {
      FMResultSet *rs = [db executeQuery:@"SELECT * FROM certrules WHERE sha1=? LIMIT 1", SHA1];
      if ([rs next]) {
          rule = [self ruleFromResultSet:rs];
      }
      [rs close];
  }];

  return rule;
}

- (SNTRule *)binaryRuleForSHA1:(NSString *)SHA1 {
  __block SNTRule *rule;

  [self inDatabase:^(FMDatabase *db) {
      FMResultSet *rs = [db executeQuery:@"SELECT * FROM binrules WHERE sha1=? LIMIT 1", SHA1];
      if ([rs next]) {
        rule = [self ruleFromResultSet:rs];
      }
      [rs close];
  }];

  return rule;
}

#pragma mark Adding

- (void)addRule:(SNTRule *)rule {
  if (!rule.SHA1 || [rule.SHA1 length] == 0) return;
  if (rule.state == RULESTATE_UNKNOWN) return;
  if (rule.type == RULETYPE_UNKNOWN) return;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
      if (rule.state == RULESTATE_REMOVE) {
        [db executeUpdate:@"DELETE FROM rules WHERE SHA1=? AND type=?",
            rule.SHA1, @(rule.type)];
      } else {
        [db executeUpdate:@"INSERT OR REPLACE INTO rules (sha1, state, type, customMsg) "
            @"VALUES (?, ?, ?, ?);", rule.SHA1, @(rule.state), @(rule.type), rule.customMsg];
      }
  }];
}

- (void)addRules:(NSArray *)rules {
  for (SNTRule *rule in rules) {
    if (![rule isKindOfClass:[SNTRule class]]) return;
    [self addRule:rule];
  }
}

@end
