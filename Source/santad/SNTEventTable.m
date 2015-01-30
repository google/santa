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

#import "SNTEventTable.h"

#import "SNTCertificate.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"

@implementation SNTEventTable

- (int)initializeDatabase:(FMDatabase *)db fromVersion:(int)version {
  int newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'events' ("
        "'idx' INTEGER PRIMARY KEY AUTOINCREMENT,"
        "'fileSHA256' TEXT NOT NULL,"
        "'eventData' BLOB"
        @");"];
    [db executeUpdate:@"CREATE INDEX event_filesha256 ON events (fileSHA256);"];

    newVersion = 1;
  }

  return newVersion;
}

#pragma mark Loading / Storing

- (BOOL)addStoredEvent:(SNTStoredEvent *)event {
  if (!event.fileSHA256 ||
      !event.filePath ||
      !event.occurrenceDate ||
      !event.executingUser ||
      !event.decision) return NO;

  NSData *eventData = [NSKeyedArchiver archivedDataWithRootObject:event];

  __block BOOL result = NO;
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
      if (![db executeUpdate:@"INSERT INTO 'events' (fileSHA256, eventData) VALUES (?, ?)",
            event.fileSHA256, eventData]) {
        LOGD(@"Failed to save event with SHA-256: %@", event.fileSHA256);
        result = NO;
      } else {
        result = YES;
      }
  }];

  return result;
}

- (SNTStoredEvent *)eventFromResultSet:(FMResultSet *)rs {
  NSData *eventData = [rs dataForColumn:@"eventData"];
  if (!eventData) return nil;

  SNTStoredEvent *event = [NSKeyedUnarchiver unarchiveObjectWithData:eventData];
  event.idx = @([rs intForColumn:@"idx"]);

  return event;
}

#pragma mark Querying/Retreiving

- (NSUInteger)pendingEventsCount {
  __block NSUInteger eventsPending = 0;
  [self inDatabase:^(FMDatabase *db) {
      eventsPending = [db intForQuery:@"SELECT COUNT(*) FROM events"];
  }];
  return eventsPending;
}

- (SNTStoredEvent *)latestEventForSHA256:(NSString *)sha256 {
  __block SNTStoredEvent *storedEvent;

  [self inDatabase:^(FMDatabase *db) {
      FMResultSet *rs = [db executeQuery:@"SELECT * FROM events WHERE fileSHA256=? LIMIT 1;",
                         sha256];

      if ([rs next]) {
        storedEvent = [self eventFromResultSet:rs];
      }

      [rs close];
  }];

  return storedEvent;
}

- (NSArray *)pendingEvents {
  NSMutableArray *pendingEvents = [[NSMutableArray alloc] init];

  [self inDatabase:^(FMDatabase *db) {
      FMResultSet *rs = [db executeQuery:@"SELECT * FROM events"];

      while ([rs next]) {
        [pendingEvents addObject:[self eventFromResultSet:rs]];
      }

      [rs close];
  }];

  return pendingEvents;
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
}

@end
