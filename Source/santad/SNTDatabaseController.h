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

#import <Foundation/Foundation.h>

// This is imported in the header rather than implementation to saves
// classes that use this one from also having to import FMDB stuff.
#import <FMDB/FMDB.h>

@class SNTConfigTable;
@class SNTEventTable;
@class SNTRuleTable;

///
///  Provides methods to get an instance of one of the database table controllers with a
///  pre-configured database queue.
///
@interface SNTDatabaseController : NSObject

///
///  Returns an instance of the respective table class initialized with an appropriate
///  database queue. Will initialize only once, regardless of calling thread.
///
+ (SNTEventTable *)eventTable;
+ (SNTRuleTable *)ruleTable;

@end
