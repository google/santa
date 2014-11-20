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

#import "SNTDatabaseTable.h"

@class SNTNotificationMessage;
@class SNTStoredEvent;

/// Responsible for managing the event table in the Santa database.
@interface SNTEventTable : SNTDatabaseTable

/// Add event to the database
- (void)addStoredEvent:(SNTStoredEvent *)event;

/// Number of events in database.
- (int)eventsPendingCount;

/// Retrieves all events in the database
/// @return NSArray of SNTStoredEvent
- (NSArray *)pendingEvents;

/// Retrieve an event from the database.
/// @return a single SNTStoredEvent
- (SNTStoredEvent *)latestEventForSHA1:(NSString *)sha1;

/// Delete a single event from the database using its index.
- (void)deleteEventWithIndex:(NSNumber *)index;

/// Delete multiple events from the database with an array of indexes.
- (void)deleteEventsWithIndexes:(NSArray *)indexes;

@end
