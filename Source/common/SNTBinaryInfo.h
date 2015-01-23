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

/**
 *  SNTBinaryInfo represents a binary on disk, providing access to details about that binary such as
 *  the SHA-1, the Info.plist and the Mach-O data.
 */
@interface SNTBinaryInfo : NSObject

/**
 *  Designated initializer
 *
 *  @param path the path of the file this SNTBinaryInfo represents
 */
- (instancetype)initWithPath:(NSString *)path;

/// Return SHA-1 hash of this binary
- (NSString *)SHA1;

/**
 *  Returns the type of Mach-O file:
 *  Dynamic Library, Kernel Extension, Fat Binary, Thin Binary
 */
- (NSString *)machoType;

/// Returns the architectures included in this binary (e.g. x86_64, ppc)
- (NSArray *)architectures;

/// Returns YES if this file is a Mach-O file
- (BOOL)isMachO;

/// Returns YES if this file contains multiple architectures
- (BOOL)isFat;

/// Returns YES if this file is an executable Mach-O file
- (BOOL)isExecutable;

/// Returns YES if this file is a dynamic library
- (BOOL)isDylib;

/// Returns YES if this file is a kernel extension
- (BOOL)isKext;

/// Returns YES if this file is a script (e.g. it begins #!)
- (BOOL)isScript;

/// Returns an NSBundle if this file is part of a bundle.
- (NSBundle *)bundle;

/// Returns the path to the bundle this file is a part of, if any.
- (NSString *)bundlePath;

/**
 *  Returns either the Info.plist in the bundle this file is part of, or an embedded plist if there
 *  is one. In the odd case that a file has both an embedded Info.plist and is part of a bundle,
 *  the Info.plist from the bundle will be returned.
 */
- (NSDictionary *)infoPlist;

/// Returns the CFBundleIdentifier from this file's Info.plist
- (NSString *)bundleIdentifier;

/// Returns the CFBundleName from this file's Info.plist
- (NSString *)bundleName;

/// Returns the CFBundleVersion from this file's Info.plist
- (NSString *)bundleVersion;

/// Returns the CFBundleShortVersionString from this file's Info.plist
- (NSString *)bundleShortVersionString;

/// Returns any URLs this file may have been downloaded from, using the
/// |com.apple.metadata:kMDItemWhereFroms extended attribute
- (NSArray *)downloadURLs;

@end
