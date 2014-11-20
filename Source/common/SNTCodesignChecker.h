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

/// SNTCodesignChecker validates a binary (either on-disk or in memory) has been signed
/// and if so allows for pulling out the certificates that were used to sign it.
@interface SNTCodesignChecker : NSObject

/// The SecStaticCodeRef that this SNTCodesignChecker is working around
@property(readonly) SecStaticCodeRef codeRef;

/// Returns a dictionary of raw signing information
@property(readonly) NSDictionary *signingInformation;

/// Returns an array of @c SNTCertificate objects representing the chain that signed this binary.
@property(readonly) NSArray *certificates;

/// Returns the leaf certificate that this binary was signed with
@property(readonly) SNTCertificate *leafCertificate;

/// Returns the on-disk path of this binary.
@property(readonly) NSString *binaryPath;

/// Initialize an @c SNTCodesignChecker with a SecStaticCodeRef
/// Designated initializer.
/// Takes ownership of @c codeRef.
- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef;

/// Initialize an @c SNTCodesignChecker with a binary on disk.
/// Returns nil if @c binaryPath does not exist, is not a binary or is not codesigned.
- (instancetype)initWithBinaryPath:(NSString *)binaryPath;

/// Initialize an @c SNTCodesignChecker with the PID of a running process.
- (instancetype)initWithPID:(pid_t)PID;

/// Initialize an @c SNTCodesignChecker for the currently-running process.
- (instancetype)initWithSelf;

/// Returns true if the binary represented by @c otherChecker has signing information that matches
/// this binary.
- (BOOL)signingInformationMatches:(SNTCodesignChecker *)otherChecker;

@end
