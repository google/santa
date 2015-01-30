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

@class SNTCertificate;

///
///  SNTCodesignChecker validates a binary (either on-disk or in memory) has been signed
///  and if so allows for pulling out the certificates that were used to sign it.
///
@interface SNTCodesignChecker : NSObject

///
///  The SecStaticCodeRef that this SNTCodesignChecker is working around
///
@property(readonly) SecStaticCodeRef codeRef;

///
///  Returns a dictionary of raw signing information
///
@property(readonly) NSDictionary *signingInformation;

///
///  Returns an array of @c SNTCertificate objects representing the chain that signed this binary.
///
@property(readonly) NSArray *certificates;

///
///  Returns the leaf certificate that this binary was signed with
///
@property(readonly) SNTCertificate *leafCertificate;

///
///  Returns the on-disk path of this binary.
///
@property(readonly) NSString *binaryPath;

///
///  Designated initializer
///  Takes ownership of the codeRef reference.
///
///  @param codeRef a SecStaticCodeRef or SecCodeRef representing a binary.
///  @return an initialized SNTCodesignChecker if the binary is validly signed, nil otherwise.
///
- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef;

///
///  Convenience initializer for a binary on disk.
///
///  @param binaryPath A binary file on disk
///  @return an initialized SNTCodesignChecker if file is a binary and is signed, nil otherwise.
///
- (instancetype)initWithBinaryPath:(NSString *)binaryPath;

///
///  Convenience initializer for a binary that is running, by its process ID.
///
///  @param PID Id of a running process.
///  @return an initialized SNTCodesignChecker if binary is signed, nil otherwise.
///
- (instancetype)initWithPID:(pid_t)PID;

///
///  Convenience initializer for the currently running process.
///
///  @return an initialized SNTCodesignChecker if current binary is signed, nil otherwise.
///
- (instancetype)initWithSelf;

///
///  Compares the signatures of the binaries represented by this SNTCodesignChecker and
///  @c otherChecker.
///
///  If both binaries are correctly signed and the leaf signatures are identical.
///
///  @return YES if both binaries are signed with the same leaf certificate.
///
- (BOOL)signingInformationMatches:(SNTCodesignChecker *)otherChecker;

@end
