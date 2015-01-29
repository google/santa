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

#import "SNTEventTable.h"

#import "SNTCertificate.h"
#import "SNTLogging.h"
#import "SNTNotificationMessage.h"
#import "SNTStoredEvent.h"

@implementation SNTEventTable

- (int)initializeDatabase:(FMDatabase *)db fromVersion:(int)version {
  int newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'events' ("
        "'idx' INTEGER PRIMARY KEY AUTOINCREMENT,"
        "'fileSHA256' TEXT NOT NULL,"
        "'filePath' TEXT NOT NULL,"
        "'fileBundleID' TEXT,"
        "'fileBundleVersion' TEXT,"
        "'fileBundleVersionString' TEXT,"
        "'fileBundleName' TEXT,"
        "'certSHA1' TEXT,"
        "'certCN' TEXT,"
        "'certOrg' TEXT,"
        "'certOU' TEXT,"
        "'certValidFromDate' REAL,"
        "'certValidUntilDate' REAL,"
        "'occurrenceDate' REAL,"
        "'executingUser' TEXT,"
        "'decision' INT,"
        "'loggedInUsers' BLOB,"
        "'currentSessions' BLOB"
        @");"];
    [db executeUpdate:@"CREATE INDEX event_filesha256 ON events (fileSHA256);"];

    newVersion = 1;
  }

  return newVersion;
}

#pragma mark Loading / Storing

- (void)addStoredEvent:(SNTStoredEvent *)event {
  if (!event.fileSHA256 ||
      !event.filePath ||
      !event.occurrenceDate ||
      !event.executingUser ||
      !event.decision) return;

  NSMutableDictionary *parameters = [@{@"fileSHA256": event.fileSHA256,
                                       @"filePath": event.filePath,
                                       @"occurrenceDate": event.occurrenceDate,
                                       @"executingUser": event.executingUser,
                                       @"decision": @(event.decision)} mutableCopy];

  if (event.certSHA1) parameters[@"certSHA1"] = event.certSHA1;
  if (event.certCN) parameters[@"certCN"] = event.certCN;
  if (event.certOrg) parameters[@"certOrg"] = event.certOrg;
  if (event.certOU) parameters[@"certOU"] = event.certOU;
  if (event.certValidFromDate) parameters[@"certValidFromDate"] = event.certValidFromDate;
  if (event.certValidUntilDate) parameters[@"certValidUntilDate"] = event.certValidUntilDate;

  if (event.fileBundleID) parameters[@"fileBundleID"] = event.fileBundleID;
  if (event.fileBundleName) parameters[@"fileBundleName"] = event.fileBundleName;
  if (event.fileBundleVersion) parameters[@"fileBundleVersion"] = event.fileBundleVersion;
  if (event.fileBundleVersionString) {
    parameters[@"fileBundleVersionString"] = event.fileBundleVersionString;
  }

  if (event.loggedInUsers) {
    NSData *usersData = [NSKeyedArchiver archivedDataWithRootObject:event.loggedInUsers];
    parameters[@"loggedInUsers"] = usersData;
  }

  if (event.currentSessions ) {
    NSData *sessionsData = [NSKeyedArchiver archivedDataWithRootObject:event.currentSessions];
    parameters[@"currentSessions"] = sessionsData;
  }

  NSString *paramString = [[parameters allKeys] componentsJoinedByString:@","];
  NSString *paramStringColon = [paramString stringByReplacingOccurrencesOfString:@","
                                                                      withString:@",:"];
  paramStringColon = [@":" stringByAppendingString:paramStringColon];

  NSString *sql = [NSString stringWithFormat:@"INSERT INTO 'events' (%@) VALUES (%@)",
                      paramString,
                      paramStringColon];

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
      if (![db executeUpdate:sql withParameterDictionary:parameters]) {
        LOGD(@"Failed to save event");
      }
  }];
}

- (SNTStoredEvent *)eventFromResultSet:(FMResultSet *)rs {
  SNTStoredEvent *event = [[SNTStoredEvent alloc] init];

  event.idx = @([rs intForColumn:@"idx"]);
  event.fileSHA256 = [rs stringForColumn:@"fileSHA256"];
  event.filePath = [rs stringForColumn:@"filePath"];
  event.occurrenceDate = [rs dateForColumn:@"occurrenceDate"];
  event.executingUser = [rs stringForColumn:@"executingUser"];
  event.decision = [rs intForColumn:@"decision"];

  event.certSHA1 = [rs stringForColumn:@"certSHA1"];
  event.certCN = [rs stringForColumn:@"certCN"];
  event.certOrg = [rs stringForColumn:@"certOrg"];
  event.certOU = [rs stringForColumn:@"certOU"];
  event.certValidFromDate = [rs dateForColumn:@"certValidFromDate"];
  event.certValidUntilDate = [rs dateForColumn:@"certValidUntilDate"];

  event.fileBundleID = [rs stringForColumn:@"fileBundleID"];
  event.fileBundleName = [rs stringForColumn:@"fileBundleName"];
  event.fileBundleVersion = [rs stringForColumn:@"fileBundleVersion"];
  event.fileBundleVersionString = [rs stringForColumn:@"fileBundleVersionString"];

  NSData *currentSessions = [rs dataForColumn:@"currentSessions"];
  NSData *loggedInUsers = [rs dataForColumn:@"loggedInUsers"];

  if (currentSessions) {
    event.currentSessions = [NSKeyedUnarchiver unarchiveObjectWithData:currentSessions];
  }

  if (loggedInUsers) {
    event.loggedInUsers = [NSKeyedUnarchiver unarchiveObjectWithData:loggedInUsers];
  }

  return event;
}

#pragma mark Querying/Retreiving

- (int)eventsPendingCount {
  __block int eventsPending = 0;
  [self inDatabase:^(FMDatabase *db) {
      eventsPending = [db intForQuery:@"SELECT COUNT(*) FROM events"];
  }];
  return eventsPending;
}

- (SNTStoredEvent *)latestEventForSHA256:(NSString *)sha256 {
  __block SNTStoredEvent *storedEvent;

  [self inDatabase:^(FMDatabase *db) {
      FMResultSet *rs = [db executeQuery:@"SELECT * FROM events WHERE fileSHA256=? "
                                         @"ORDER BY occurrenceDate DESC LIMIT 1;", sha256];

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

- (void)deleteEventWithIndex:(NSNumber *)index {
  [self inDatabase:^(FMDatabase *db) {
      [db executeUpdate:@"DELETE FROM events WHERE idx=?", index];
  }];
}

- (void)deleteEventsWithIndexes:(NSArray *)indexes {
  for (NSNumber *index in indexes) {
    [self deleteEventWithIndex:index];
  }
}

@end
