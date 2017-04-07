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

@import Foundation;

#import "SNTDatabaseTable.h"

@class SNTNotificationMessage;
@class SNTStoredEvent;

///
/// Responsible for managing the event table.
///
@interface SNTEventTable : SNTDatabaseTable

///
///  Add event to the database.
///
///  @param event the event to store.
///  @return YES if event was successfully stored.
///
- (BOOL)addStoredEvent:(SNTStoredEvent *)event;

///
///  Add events to the database.
///
///  @param events the events to store.
///  @return YES if events were successfully stored.
///
- (BOOL)addStoredEvents:(NSArray<SNTStoredEvent *> *)events;

///
///  Retrieves all events in the database
///
///  @return NSArray of SNTStoredEvent's
///
- (NSArray *)pendingEvents;

///
///  Retrieves number of events in database without fetching every event.
///
///  @return Number of events in database.
///
- (NSUInteger)pendingEventsCount;

///
///  Delete a single event from the database using its index.
///
///  @param index the event ID.
///
- (void)deleteEventWithId:(NSNumber *)index;

///
///  Delete multiple events from the database with an array of IDs.
///
///  @param indexes an array of event IDs.
///
- (void)deleteEventsWithIds:(NSArray *)indexes;

@end
