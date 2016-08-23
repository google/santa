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

#import "SNTDatabaseController.h"

#include <sys/stat.h>
#include <sys/types.h>

#import "SNTEventTable.h"
#import "SNTLogging.h"
#import "SNTRuleTable.h"

@implementation SNTDatabaseController

static NSString *const kDatabasePath = @"/var/db/santa";
static NSString *const kRulesDatabaseName = @"rules.db";
static NSString *const kEventsDatabaseName = @"events.db";

+ (SNTEventTable *)eventTable {
  static SNTEventTable *eventDatabase;
  static dispatch_once_t eventDatabaseToken;
  dispatch_once(&eventDatabaseToken, ^{
    [self createDatabasePath];
    NSString *fullPath = [kDatabasePath stringByAppendingPathComponent:kEventsDatabaseName];
    FMDatabaseQueue *dbq = [[FMDatabaseQueue alloc] initWithPath:fullPath];
    chown([fullPath UTF8String], 0, 0);
    chmod([fullPath UTF8String], 0600);

#ifndef DEBUG
    [dbq inDatabase:^(FMDatabase *db) {
      db.logsErrors = NO;
    }];
#endif

    eventDatabase = [[SNTEventTable alloc] initWithDatabaseQueue:dbq];
  });

  return eventDatabase;
}

+ (SNTRuleTable *)ruleTable {
  static SNTRuleTable *ruleDatabase;
  static dispatch_once_t ruleDatabaseToken;
  dispatch_once(&ruleDatabaseToken, ^{
    [self createDatabasePath];
    NSString *fullPath = [kDatabasePath stringByAppendingPathComponent:kRulesDatabaseName];
    FMDatabaseQueue *dbq = [[FMDatabaseQueue alloc] initWithPath:fullPath];
    chown([fullPath UTF8String], 0, 0);
    chmod([fullPath UTF8String], 0600);

#ifndef DEBUG
    [dbq inDatabase:^(FMDatabase *db) {
      db.logsErrors = NO;
    }];
#endif

    ruleDatabase = [[SNTRuleTable alloc] initWithDatabaseQueue:dbq];
  });
  return ruleDatabase;
}

#pragma mark - Private

/// Create the folder that contains the databases
+ (void)createDatabasePath {
  NSFileManager *fm = [NSFileManager defaultManager];

  NSDictionary *attrs = @{
    NSFileOwnerAccountName : @"root",
    NSFileGroupOwnerAccountName : @"wheel",
    NSFilePosixPermissions : @0755
  };

  if (![fm fileExistsAtPath:kDatabasePath]) {
    [fm createDirectoryAtPath:kDatabasePath
        withIntermediateDirectories:YES
                         attributes:attrs
                              error:nil];
  } else {
    [fm setAttributes:attrs ofItemAtPath:kDatabasePath error:nil];
  }
}

@end
