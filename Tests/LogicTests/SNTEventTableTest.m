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

#import <XCTest/XCTest.h>

#import <MOLCodesignChecker/MOLCodesignChecker.h>

#import "SNTEventTable.h"
#import "SNTFileInfo.h"
#import "SNTStoredEvent.h"

/// This test case actually tests SNTEventTable and SNTStoredEvent.
///
/// Adding/Retrieving events relies on SNTStoredEvent coding to work correctly
/// so if that is broken, these tests will fail.
///
/// Depends on on SNTFileInfo and MOLCodesignChecker (and by extension
/// MOLCertificate) to avoid duplicating code into these tests.
///
@interface SNTEventTableTest : XCTestCase
@property SNTEventTable *sut;
@property FMDatabaseQueue *dbq;
@end

@implementation SNTEventTableTest

- (void)setUp {
  [super setUp];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.sut = [[SNTEventTable alloc] initWithDatabaseQueue:self.dbq];
}

- (SNTStoredEvent *)createTestEvent {
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/false"];
  MOLCodesignChecker *csInfo = [binInfo codesignCheckerWithError:NULL];
  SNTStoredEvent *event;
  event = [[SNTStoredEvent alloc] init];
  event.idx = @(arc4random());
  event.filePath = @"/usr/bin/false";
  event.fileSHA256 = [binInfo SHA256];
  event.signingChain = [csInfo certificates];
  event.executingUser = @"nobody";
  event.loggedInUsers = @[ @"nobody" ];
  event.currentSessions = @[ @"nobody@ttys000", @"nobody@console" ];
  event.occurrenceDate = [NSDate date];
  event.decision = SNTEventStateAllowBinary;
  return event;
}

- (void)testAddEvent {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
  XCTAssert([self.sut addStoredEvent:[self createTestEvent]]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
}

- (void)testRetrieveEvent {
  SNTStoredEvent *event = [self createTestEvent];
  [self.sut addStoredEvent:event];

  SNTStoredEvent *storedEvent = [self.sut pendingEvents].firstObject;
  XCTAssertNotNil(storedEvent);
  XCTAssertEqualObjects(event.filePath, storedEvent.filePath);
  XCTAssertEqualObjects(event.signingChain, storedEvent.signingChain);
  XCTAssertEqualObjects(event.loggedInUsers, storedEvent.loggedInUsers);
  XCTAssertEqualObjects(event.occurrenceDate, storedEvent.occurrenceDate);
  XCTAssertEqual(event.decision, storedEvent.decision);
}

- (void)testDeleteEventWithId {
  SNTStoredEvent *newEvent = [self createTestEvent];
  [self.sut addStoredEvent:newEvent];
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  [self.sut deleteEventWithId:newEvent.idx];
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
}

- (void)testDeleteEventsWithIds {
  // Add 50 events to the database
  for (int i = 0; i < 50; ++i) {
    SNTStoredEvent *newEvent = [self createTestEvent];
    [self.sut addStoredEvent:newEvent];
  }

  // Fetch those events (so we have the IDs)
  NSArray *pendingEvents = [self.sut pendingEvents];

  // Ensure enough events were added and retrieved
  XCTAssertEqual(self.sut.pendingEventsCount, 50);
  XCTAssertEqual(self.sut.pendingEventsCount, pendingEvents.count);

  // Collect the IDs
  NSMutableArray *eventIds = [NSMutableArray array];
  for (SNTStoredEvent *event in pendingEvents) {
    [eventIds addObject:event.idx];
  }

  // Now delete them
  [self.sut deleteEventsWithIds:eventIds];

  // Check they were deleted
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
}

- (void)testDeleteCorruptEvent {
  [self.dbq inDatabase:^(FMDatabase *db) {
    [db executeUpdate:@"INSERT INTO events (filesha256) VALUES ('deadbeef')"];
  }];

  NSArray *events = [self.sut pendingEvents];
  for (SNTStoredEvent *event in events) {
    if ([event.fileSHA256 isEqual:@"deadbeef"]) XCTFail("Received bad event");
  }

  [self.dbq inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM events WHERE filesha256='deadbeef'"];
    if ([rs next]) {
      XCTFail("Bad event was not deleted.");
    }
    [rs close];
  }];
}

@end
