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

#import "Source/santad/DataLayer/SNTDatabaseTable.h"

#import "Source/common/SNTLogging.h"

@interface SNTDatabaseTable ()
@property FMDatabaseQueue *dbQ;
@end

@implementation SNTDatabaseTable

- (instancetype)initWithDatabaseQueue:(FMDatabaseQueue *)db {
  if (!db) return nil;

  self = [super init];
  if (self) {
    [db inDatabase:^(FMDatabase *db) {
      if (![db goodConnection]) {
        [db close];
        [[NSFileManager defaultManager] removeItemAtPath:[db databasePath] error:NULL];
        [db open];
      }
    }];

    _dbQ = db;

    [self updateTableSchema];
  }
  return self;
}

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

/// Called at the end of initialization to ensure the table in the
/// database exists and uses the latest schema.
- (void)updateTableSchema {
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    uint32_t currentVersion = [db userVersion];
    uint32_t newVersion = [self initializeDatabase:db fromVersion:currentVersion];
    if (newVersion < 1) return;

    LOGI(@"Updated %@ from version %d to %d", [self className], currentVersion, newVersion);

    [db setUserVersion:newVersion];
  }];
}

- (void)inDatabase:(void (^)(FMDatabase *db))block {
  [self.dbQ inDatabase:block];
}

- (void)inTransaction:(void (^)(FMDatabase *db, BOOL *rollback))block {
  [self.dbQ inTransaction:block];
}

@end
