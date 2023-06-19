/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <Foundation/Foundation.h>

#import <MOLCertificate/MOLCertificate.h>

///
///  Represents an event stored in the database.
///
@interface SNTFileAccessEvent : NSObject <NSSecureCoding>

///
/// The watched path that was accessed
///
@property NSString *accessedPath;

///
/// The rule version and name that were violated
///
@property NSString *ruleVersion;
@property NSString *ruleName;

///
/// The SHA256 of the process that accessed the path
///
@property NSString *fileSHA256;

///
/// The path of the process that accessed the watched path
///
@property NSString *filePath;

///
/// If the process is part of a bundle, the name of the application
///
@property NSString *application;

///
/// If the executed file was signed, this is the Team ID if present in the signature information.
///
@property NSString *teamID;

///
/// If the executed file was signed, this is the Signing ID if present in the signature information.
///
@property NSString *signingID;

///
///  The user who executed the binary.
///
@property NSString *executingUser;

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

// TODO(mlw): Store signing chain info
// @property NSArray<MOLCertificate*> *signingChain;

@end
