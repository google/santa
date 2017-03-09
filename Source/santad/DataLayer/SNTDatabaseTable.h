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

// This is imported in the header rather than implementation to save
// classes that use this one from also having to import FMDB stuff.
#import <FMDB/FMDB.h>

@interface SNTDatabaseTable : NSObject

///
///  Designated initializer.
///
- (instancetype)initWithDatabaseQueue:(FMDatabaseQueue *)db;

///
///  Subclasses should override this method to apply schema updates. The passed in version nubmer
///  is the current version of the table. The return value is the new version of the table. If
///  updating the table failed, return a negative number. If there was no update to apply, return 0.
///
- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version;

///
///  Wrappers around the respective FMDatabaseQueue methods. If the object we initialized with was
///  a database queue, these just pass through. If the object we initialized with was an FMDatabase
///  we just call the block with the database, potentially wrapping in a transaction.
///
- (void)inDatabase:(void (^)(FMDatabase *db))block;
- (void)inTransaction:(void (^)(FMDatabase *db, BOOL *rollback))block;

@end
