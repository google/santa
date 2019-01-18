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

#import "Source/santad/DataLayer/SNTEventTable.h"

#import <MOLCertificate/MOLCertificate.h>

#import "Source/common/SNTStoredEvent.h"

@implementation SNTEventTable

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  int newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'events' ("
                      @"'idx' INTEGER PRIMARY KEY AUTOINCREMENT,"
                      @"'filesha256' TEXT NOT NULL,"
                      @"'eventdata' BLOB);"];
    [db executeUpdate:@"CREATE INDEX filesha256 ON events (filesha256);"];
    newVersion = 1;
  }

  if (version < 2) {
    // Clean-up: Find events where the bundle details might not be strings and update them.
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM events"];
    while ([rs next]) {
      SNTStoredEvent *se = [self eventFromResultSet:rs];
      if (!se) continue;

      Class NSStringClass = [NSString class];
      if ([se.fileBundleID class] != NSStringClass) {
        se.fileBundleID = [se.fileBundleID description];
      }
      if ([se.fileBundleName class] != NSStringClass) {
        se.fileBundleName = [se.fileBundleName description];
      }
      if ([se.fileBundleVersion class] != NSStringClass) {
        se.fileBundleVersion = [se.fileBundleVersion description];
      }
      if ([se.fileBundleVersionString class] != NSStringClass) {
        se.fileBundleVersionString = [se.fileBundleVersionString description];
      }

      NSData *eventData;
      NSNumber *idx = [rs objectForColumn:@"idx"];
      @try {
        eventData = [NSKeyedArchiver archivedDataWithRootObject:se];
        [db executeUpdate:@"UPDATE events SET eventdata=? WHERE idx=?", eventData, idx];
      } @catch (NSException *exception) {
        [db executeUpdate:@"DELETE FROM events WHERE idx=?", idx];
      }
    }
    [rs close];
    newVersion = 2;
  }

  if (version < 3) {
    // Clean-up: Disable AUTOINCREMENT on idx column
    [db executeUpdate:@"CREATE TABLE 'events_tmp' ("
                      @"'idx' INTEGER PRIMARY KEY,"
                      @"'filesha256' TEXT NOT NULL,"
                      @"'eventdata' BLOB);"];
    [db executeUpdate:@"INSERT INTO events_tmp SELECT * FROM events"];
    [db executeUpdate:@"DROP TABLE events"];
    [db executeUpdate:@"ALTER TABLE events_tmp RENAME TO events"];
    newVersion = 3;
  }

  return newVersion;
}

#pragma mark Loading / Storing

- (BOOL)addStoredEvent:(SNTStoredEvent *)event {
  return [self addStoredEvents:@[event]];
}

- (BOOL)addStoredEvents:(NSArray<SNTStoredEvent *> *)events {
  NSMutableDictionary *eventsData = [NSMutableDictionary dictionaryWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    if (!event.idx ||
        !event.fileSHA256 ||
        !event.filePath ||
        !event.occurrenceDate ||
        !event.decision) continue;

    NSData *eventData;
    @try {
      eventData = [NSKeyedArchiver archivedDataWithRootObject:event];
    } @catch (NSException *exception) {
      continue;
    }
    eventsData[eventData] = event;
  }

  __block BOOL success = NO;
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    [eventsData enumerateKeysAndObjectsUsingBlock:^(NSData * eventData,
                                                    SNTStoredEvent * event,
                                                    BOOL *stop) {
      success = [db executeUpdate:@"INSERT INTO 'events' (idx, filesha256, eventdata)"
                    @"VALUES (?, ?, ?)",
                    event.idx, event.fileSHA256, eventData];
      if (!success) *stop = YES;
    }];
  }];

  return success;
}

#pragma mark Querying/Retreiving

- (NSUInteger)pendingEventsCount {
  __block NSUInteger eventsPending = 0;
  [self inDatabase:^(FMDatabase *db) {
    eventsPending = [db intForQuery:@"SELECT COUNT(*) FROM events"];
  }];
  return eventsPending;
}

- (NSArray *)pendingEvents {
  NSMutableArray *pendingEvents = [[NSMutableArray alloc] init];

  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM events"];

    while ([rs next]) {
      id obj = [self eventFromResultSet:rs];
      if (obj) {
        [pendingEvents addObject:obj];
      } else {
        [db executeUpdate:@"DELETE FROM events WHERE idx=?", [rs objectForColumn:@"idx"]];
      }
    }

    [rs close];
  }];

  return pendingEvents;
}

- (SNTStoredEvent *)eventFromResultSet:(FMResultSet *)rs {
  NSData *eventData = [rs dataForColumn:@"eventdata"];
  if (!eventData) return nil;

  SNTStoredEvent *event;

  @try {
    event = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];
    event.idx = event.idx ?: @((uint32_t)[rs intForColumn:@"idx"]);
  } @catch (NSException *exception) {
  }

  return event;
}

#pragma mark Deleting

- (void)deleteEventWithId:(NSNumber *)index {
  [self inDatabase:^(FMDatabase *db) {
    [db executeUpdate:@"DELETE FROM events WHERE idx=?", index];
  }];
}

- (void)deleteEventsWithIds:(NSArray *)indexes {
  for (NSNumber *index in indexes) {
    [self deleteEventWithId:index];
  }
  [self inDatabase:^(FMDatabase *db) {
    [db executeUpdate:@"VACUUM"];
  }];
}

@end
