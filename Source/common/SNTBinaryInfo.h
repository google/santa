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

///
///  SNTBinaryInfo represents a binary on disk, providing access to details about that binary
///  such as the SHA-1, SHA-256, Info.plist and the Mach-O data.
///
@interface SNTBinaryInfo : NSObject

///
///  Designated initializer
///
///  @param path the path of the file this SNTBinaryInfo represents
///
- (instancetype)initWithPath:(NSString *)path;

///
///  @return SHA-1 hash of this binary
///
- (NSString *)SHA1;

///
///  @return SHA-256 hash of this binary
///
- (NSString *)SHA256;

///
///  @return The type of Mach-O file, one of:
///  Dynamic Library, Kernel Extension, Fat Binary or Thin Binary
///
- (NSString *)machoType;

///
///  @return The architectures included in this binary (e.g. x86_64, ppc)
///
- (NSArray *)architectures;

///
///  @return YES if this file is a Mach-O file
///
- (BOOL)isMachO;

///
///  @return YES if this file contains multiple architectures
///
- (BOOL)isFat;

///
///  @return YES if this file is an executable Mach-O file
///
- (BOOL)isExecutable;

///
///  @return YES if this file is a dynamic library
///
- (BOOL)isDylib;

///
///  @return YES if this file is a kernel extension
///
- (BOOL)isKext;

///
///  @return YES if this file is a script (e.g. it begins #!)
///
- (BOOL)isScript;

///
///  @return An NSBundle if this file is part of a bundle.
///
- (NSBundle *)bundle;

///
///  @return The path to the bundle this file is a part of, if any.
///
- (NSString *)bundlePath;

///
///  @return Either the Info.plist in the bundle this file is part of, or an embedded plist if there
///  is one. In the odd case that a file has both an embedded Info.plist and is part of a bundle,
///  the Info.plist from the bundle will be returned.
///
- (NSDictionary *)infoPlist;

///
///  @return the CFBundleIdentifier from this file's Info.plist
///
- (NSString *)bundleIdentifier;

///
///  @return the CFBundleName from this file's Info.plist
///
- (NSString *)bundleName;

///
///  @return the CFBundleVersion from this file's Info.plist
///
- (NSString *)bundleVersion;

///
///  @return the CFBundleShortVersionString from this file's Info.plist
///
- (NSString *)bundleShortVersionString;

///
///  @return any URLs this file may have been downloaded from, using the
///  @c com.apple.metadata:kMDItemWhereFroms extended attribute
///
- (NSArray *)downloadURLs;

@end
