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

@class MOLCodesignChecker;

///
///  Represents a binary on disk, providing access to details about that binary
///  such as the SHA-1, SHA-256, Info.plist and the Mach-O data.
///
@interface SNTFileInfo : NSObject

///
///  Designated initializer.
///
///  @param path The path of the file this instance is to represent. The path will be
///      converted to an absolute, standardized path if it isn't already.
///  @param error If an error occurred and nil is returned, this will be a pointer to an NSError
///      describing the problem.
///
- (instancetype)initWithPath:(NSString *)path error:(NSError **)error;

///
///  Convenience initializer.
///
///  @param path The path to the file this instance is to represent. The path will be
///      converted to an absolute, standardized path if it isn't already.
///
- (instancetype)initWithPath:(NSString *)path;


///
///  Initializer for already resolved paths.
///
///  @param path The path of the file this instance is to represent. The path will
///      not be converted and will be used as is. If the path is not a regular file this method will
///      return nil and fill in an error.
///  @param error If an error occurred and nil is returned, this will be a pointer to an NSError
///      describing the problem.
///
- (instancetype)initWithResolvedPath:(NSString *)path error:(NSError **)error;

///
///  @return Path of this file.
///
- (NSString *)path;

///
///  Hash this file with SHA-1 and SHA-256 simultaneously.
///
///  @param sha1 If not NULL, will be filled with the SHA-1 of the file.
///  @param sha256 If not NULL, will be filled with the SHA-256 of the file.
///
- (void)hashSHA1:(NSString **)sha1 SHA256:(NSString **)sha256;

///
///  @return SHA-1 hash of this binary.
///
- (NSString *)SHA1;

///
///  @return SHA-256 hash of this binary.
///
- (NSString *)SHA256;

///
///  @return The architectures included in this binary (e.g. x86_64, ppc).
///
- (NSArray *)architectures;

///
///  @return YES if this file is a Mach-O file.
///
- (BOOL)isMachO;

///
///  @return YES if this file contains multiple architectures.
///
- (BOOL)isFat;

///
///  @return YES if this file is an executable Mach-O file.
///
- (BOOL)isExecutable;

///
///  @return YES if this file is a dynamic library.
///
- (BOOL)isDylib;

///
///  @return YES if this file is a bundle executable (QuickLook/Spotlight plugin, etc.)
///
- (BOOL)isBundle;

///
///  @return YES if this file is a kernel extension.
///
- (BOOL)isKext;

///
///  @return YES if this file is a script (e.g. it begins #!).
///
- (BOOL)isScript;

///
///  @return YES if this file is an XAR archive.
///
- (BOOL)isXARArchive;

///
///  @return YES if this file is a disk image.
///
- (BOOL)isDMG;

///
///  @return NSString describing the kind of file (executable, bundle, script, etc.)
///
- (NSString *)humanReadableFileType;

///
///  @return YES if this file has a bad/missing __PAGEZERO .
///
- (BOOL)isMissingPageZero;

///
///  If set to YES, the bundle* and infoPlist methods will search for and use the highest NSBundle
///  found in the tree. Defaults to NO, which uses the first found bundle, if any.
///
///  @example:
///      An SNTFileInfo object that represents
///        /Applications/Photos.app/Contents/XPCServices/com.apple.Photos.librarychooserservice.xpc
///      useAncestorBundle is set to YES
///        /Applications/Photos.app will be used to get data backing all the bundle methods
///
///  @note: The NSBundle object backing the bundle* and infoPlist methods is cached once found.
///         Setting the useAncestorBundle propery will clear this cache and force a re-search.
///
@property(nonatomic) BOOL useAncestorBundle;

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
///  is one. In the unlikely event that a file has both an embedded Info.plist and is part of a
///  bundle, the embedded plist will be returned.
///
- (NSDictionary *)infoPlist;

///
///  @return the CFBundleIdentifier from this file's Info.plist.
///
- (NSString *)bundleIdentifier;

///
///  @return the CFBundleName from this file's Info.plist.
///
- (NSString *)bundleName;

///
///  @return the CFBundleVersion from this file's Info.plist.
///
- (NSString *)bundleVersion;

///
///  @return the CFBundleShortVersionString from this file's Info.plist.
///
- (NSString *)bundleShortVersionString;

///
///  @return LaunchServices quarantine data - download URL as an absolute string.
///
- (NSString *)quarantineDataURL;

///
///  @return LaunchServices quarantine data - referer URL as an absolute string.
///
- (NSString *)quarantineRefererURL;

///
///  @return LaunchServices quarantine data - agent bundle ID.
///
- (NSString *)quarantineAgentBundleID;

///
///  @return LaunchServices quarantine data - timestamp.
///
- (NSDate *)quarantineTimestamp;

///
///  @return The size of the file in bytes.
///
- (NSUInteger)fileSize;

///
///  @return Returns an instance of MOLCodeSignChecker initialized with the file's binary path.
///  Both the MOLCodesignChecker and any resulting NSError are cached and returned on subsequent
///  calls.  You may pass in NULL for the error if you don't care to receive it.
///
- (MOLCodesignChecker *)codesignCheckerWithError:(NSError **)error;

@end
