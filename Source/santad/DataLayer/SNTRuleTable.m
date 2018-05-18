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

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

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

  // Save hashes of the signing certs for launchd and santad.
  // Used to ensure rules for them are not removed.
  self.santadCertSHA = [[[[MOLCodesignChecker alloc] initWithSelf] leafCertificate] SHA256];
  self.launchdCertSHA = [[[[MOLCodesignChecker alloc] initWithPID:1] leafCertificate] SHA256];

  // Ensure the certificates used to sign the running launchd/santad are whitelisted.
  // If they weren't previously and the database is not new, log an error.
  int ruleCount = [db intForQuery:@"SELECT COUNT(*)"
                                  @"FROM rules "
                                  @"WHERE (shasum=? OR shasum=?) AND state=? AND type=2",
                      self.santadCertSHA, self.launchdCertSHA, @(SNTRuleStateWhitelist)];
  if (ruleCount != 2) {
    if (version > 0) LOGE(@"Started without launchd/santad certificate rules in place!");
    [db executeUpdate:@"INSERT INTO rules (shasum, state, type) VALUES (?, ?, ?)",
        self.santadCertSHA, @(SNTRuleStateWhitelist), @(SNTRuleTypeCertificate)];
    [db executeUpdate:@"INSERT INTO rules (shasum, state, type) VALUES (?, ?, ?)",
        self.launchdCertSHA, @(SNTRuleStateWhitelist), @(SNTRuleTypeCertificate)];
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
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE type=1"];
  }];
  return count;
}

- (NSUInteger)certificateRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE type=2"];
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

- (SNTRule *)ruleForBinarySHA256:(NSString *)binarySHA256
               certificateSHA256:(NSString *)certificateSHA256 {
  __block SNTRule *rule;
 
  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs =
        [db executeQuery:
            @"SELECT * FROM rules WHERE (shasum=? and type=1) OR (shasum=? AND type=2) LIMIT 1",
            binarySHA256, certificateSHA256];
    if ([rs next]) {
      rule = [self ruleFromResultSet:rs];
    }
    [rs close];
  }];

  return rule;
}

#pragma mark Adding

- (BOOL)addRules:(NSArray *)rules cleanSlate:(BOOL)cleanSlate
           error:(NSError * __autoreleasing *)error {
  if (!rules || rules.count < 1) {
    [self fillError:error code:SNTRuleTableErrorEmptyRuleArray message:nil];
    return NO;
  }

  __block BOOL failed = NO;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    // Protect rules for santad/launchd certificates.
    NSPredicate *p = [NSPredicate predicateWithFormat:
                         @"(SELF.shasum = %@ OR SELF.shasum = %@) AND SELF.type = %d",
                         self.santadCertSHA, self.launchdCertSHA, SNTRuleTypeCertificate];
    NSArray *requiredHashes = [rules filteredArrayUsingPredicate:p];
    p = [NSPredicate predicateWithFormat:@"SELF.state == %d", SNTRuleStateWhitelist];
    NSArray *requiredHashesWhitelist = [requiredHashes filteredArrayUsingPredicate:p];
    if ((cleanSlate && requiredHashesWhitelist.count < 2) ||
        (requiredHashes.count != requiredHashesWhitelist.count)) {
      LOGE(@"Received request to remove whitelist for launchd/santad certificates.");
      [self fillError:error code:SNTRuleTableErrorMissingRequiredRule message:nil];
      *rollback = failed = YES;
      return;
    }

    if (cleanSlate) {
      [db executeUpdate:@"DELETE FROM rules"];
    }

    for (SNTRule *rule in rules) {
      if (![rule isKindOfClass:[SNTRule class]] || rule.shasum.length == 0 ||
          rule.state == SNTRuleStateUnknown || rule.type == SNTRuleTypeUnknown) {
        [self fillError:error code:SNTRuleTableErrorInvalidRule message:nil];
        *rollback = failed = YES;
        return;
      }

      if (rule.state == SNTRuleStateRemove) {
        if (![db executeUpdate:@"DELETE FROM rules WHERE shasum=? AND type=?",
                               rule.shasum, @(rule.type)]) {
          [self fillError:error
                     code:SNTRuleTableErrorRemoveFailed
                  message:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      } else {
        if (![db executeUpdate:@"INSERT OR REPLACE INTO rules "
                               @"(shasum, state, type, custommsg) "
                               @"VALUES (?, ?, ?, ?);",
                               rule.shasum, @(rule.state), @(rule.type), rule.customMsg]) {
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

//  Helper to create an NSError where necessary.
//  The return value is irrelevant but the static analyzer complains if it's not a BOOL.
- (BOOL)fillError:(NSError **)error code:(SNTRuleTableError)code message:(NSString *)message {
  if (!error) return NO;

  NSMutableDictionary *d = [NSMutableDictionary dictionary];
  switch (code) {
    case SNTRuleTableErrorEmptyRuleArray:
      d[NSLocalizedDescriptionKey] = @"Empty rule array";
      break;
    case SNTRuleTableErrorInvalidRule:
      d[NSLocalizedDescriptionKey] = @"Rule array contained invalid entry";
      break;
    case SNTRuleTableErrorInsertOrReplaceFailed:
      d[NSLocalizedDescriptionKey] = @"A database error occurred while inserting/replacing a rule";
      break;
    case SNTRuleTableErrorRemoveFailed:
      d[NSLocalizedDescriptionKey] = @"A database error occurred while deleting a rule";
      break;
    case SNTRuleTableErrorMissingRequiredRule:
      d[NSLocalizedDescriptionKey] = @"A required rule was requested to be deleted";
      break;
  }

  if (message) d[NSLocalizedFailureReasonErrorKey] = message;

  *error = [NSError errorWithDomain:@"com.google.santad.ruletable" code:code userInfo:d];
  return YES;
}

@end
