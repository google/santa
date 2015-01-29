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

@class SNTCertificate;

/**
 *  An SNTEvent is created when Santa is making a decision about an execution request.
 *  All of the information required to make that decision, log it, notify the user etc. must be
 *  encapsulated within this class.
 */
@interface SNTNotificationMessage : NSObject<NSSecureCoding>

/// The path of the binary that was blocked.
@property(copy) NSString *path;

/// The SHA-256 of the binary that was blocked.
@property(copy) NSString *SHA256;

/// An array of @c SNTCertificate objects representing the certificate chain the binary was signed with.
@property(copy) NSArray *certificates;

/// A custom message to display to the user when blocking this binary, if any.
@property(copy) NSString *customMessage;

// A convenience accessor to the first certificate in @c certificates.
@property(readonly) SNTCertificate *leafCertificate;

@end
