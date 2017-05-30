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

#import "SNTCommonEnums.h"

///
///  Represents an event stored in the database.
///
@interface SNTStoredEvent : NSObject<NSSecureCoding>

///
///  An index for this event, randomly generated during initialization.
///
@property NSNumber *idx;

///
///  The SHA-256 of the executed file.
///
@property NSString *fileSHA256;

///
///  The full path of the executed file.
///
@property NSString *filePath;

///
///  Set to YES if the event is a part of a bundle. When an event is passed to SantaGUI this propery
///  will be used as an indicator to to kick off bundle hashing as necessary. Default value is NO.
///
@property BOOL needsBundleHash;

///
///  If the executed file was part of a bundle, this is the calculated hash of all the nested
///  executables within the bundle.
///
@property NSString *fileBundleHash;

///
///  If the executed file was part of a bundle, this is the time in ms it took to hash the bundle.
///
@property NSNumber *fileBundleHashMilliseconds;

///
///  If the executed file was part of a bundle, this is the total count of related mach-o binaries.
///
@property NSNumber *fileBundleBinaryCount;

///
///  If the executed file was part of the bundle, this is the CFBundleDisplayName, if it exists
///  or the CFBundleName if not.
///
@property NSString *fileBundleName;

///
///  If the executed file was part of the bundle, this is the path to the bundle.
///
@property NSString *fileBundlePath;

///
///  If the executed file was part of the bundle, this is the CFBundleID.
///
@property NSString *fileBundleID;

///
///  If the executed file was part of the bundle, this is the CFBundleVersion.
///
@property NSString *fileBundleVersion;

///
///  If the executed file was part of the bundle, this is the CFBundleShortVersionString.
///
@property NSString *fileBundleVersionString;

///
///  If the executed file was signed, this is an NSArray of MOLCertificate's
///  representing the signing chain.
///
@property NSArray *signingChain;

///
///  The user who executed the binary.
///
@property NSString *executingUser;

///
///  The date and time the execution request was received by santad.
///
@property NSDate *occurrenceDate;

///
///  The decision santad returned.
///
@property SNTEventState decision;

///
///  NSArray of logged in users when the decision was made.
///
@property NSArray *loggedInUsers;

///
///  NSArray of sessions when the decision was made (e.g. nobody@console, nobody@ttys000).
///
@property NSArray *currentSessions;

///
///  The process ID of the binary being executed.
///
@property NSNumber *pid;

///
///  The parent process ID of the binary being executed.
///
@property NSNumber *ppid;

///
///  The name of the parent process.
///
@property NSString *parentName;

///
///  Quarantine data about the executed file, if any.
///
@property NSString *quarantineDataURL;
@property NSString *quarantineRefererURL;
@property NSDate *quarantineTimestamp;
@property NSString *quarantineAgentBundleID;

@end
