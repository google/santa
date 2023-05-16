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

#import "Source/santad/SNTDatabaseController.h"

#include <sys/stat.h>
#include <sys/types.h>

#import "Source/common/SNTLogging.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

@implementation SNTDatabaseController

static NSString *const kDatabasePath = @"/var/db/santa";
static NSString *const kRulesDatabaseName = @"rules.db";
static NSString *const kEventsDatabaseName = @"events.db";

+ (NSString *const)databasePath {
  return kDatabasePath;
}

+ (id)setupTable:(Class)cls name:(NSString*)name {
  static id table;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    [self createDatabasePath];
    NSString *fullPath =
      [[SNTDatabaseController databasePath] stringByAppendingPathComponent:name];
    FMDatabaseQueue *dbq = [[FMDatabaseQueue alloc] initWithPath:fullPath];

#ifndef DEBUG
    [dbq inDatabase:^(FMDatabase *db) {
      db.logsErrors = NO;
    }];
#endif

    table = [[cls alloc] initWithDatabaseQueue:dbq];

    chown([fullPath UTF8String], 0, 0);
    chmod([fullPath UTF8String], 0600);
  });

  return table;
}

+ (SNTEventTable *)eventTable {
  return [SNTDatabaseController setupTable:[SNTEventTable class] name:kEventsDatabaseName];
}

+ (SNTRuleTable *)ruleTable {
  return [SNTDatabaseController setupTable:[SNTRuleTable class] name:kRulesDatabaseName];
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

  if (![fm fileExistsAtPath:[SNTDatabaseController databasePath]]) {
    [fm createDirectoryAtPath:[SNTDatabaseController databasePath]
      withIntermediateDirectories:YES
                       attributes:attrs
                            error:nil];
  } else {
    [fm setAttributes:attrs ofItemAtPath:[SNTDatabaseController databasePath] error:nil];
  }
}

@end
