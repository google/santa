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

#import "SNTFileInfo.h"

#import <CommonCrypto/CommonDigest.h>

#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <sys/xattr.h>

@interface SNTFileInfo ()
@property NSString *path;
@property NSData *fileData;

// Cached properties
@property NSData *firstMachHeaderData;
@property NSBundle *bundleRef;
@property NSDictionary *infoDict;
@property NSArray *architecturesArray;
@end

@implementation SNTFileInfo

- (instancetype)initWithPath:(NSString *)path {
  self = [super init];
  if (self) {
    _path = [self resolvePath:path];
    if (!_path) return nil;
    _fileData = [NSData dataWithContentsOfFile:_path options:NSDataReadingMappedIfSafe error:nil];
    if (_fileData.length == 0) return nil;
  }

  return self;
}

- (NSString *)SHA1 {
  unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
  CC_SHA1(self.fileData.bytes, (unsigned int)self.fileData.length, sha1);

  // Convert the binary SHA into hex
  NSMutableString *buf = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
    [buf appendFormat:@"%02x", (unsigned char)sha1[i]];
  }

  return buf;
}

- (NSString *)SHA256 {
  unsigned char sha256[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(self.fileData.bytes, (unsigned int)self.fileData.length, sha256);

  NSMutableString *buf = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
    [buf appendFormat:@"%02x", (unsigned char)sha256[i]];
  }

  return buf;
}

- (NSString *)machoType {
  if ([self isDylib])  return @"Dynamic Library";
  if ([self isKext])   return @"Kernel Extension";
  if ([self isFat])    return @"Fat Binary";
  if ([self isMachO])  return @"Thin Binary";
  if ([self isScript]) return @"Script";
  return @"Unknown (not executable?)";
}

- (NSArray *)architectures {
  if (!self.architecturesArray) {
    self.architecturesArray = (NSArray *)[NSNull null];

    if ([self isFat]) {
      NSMutableArray *ret = [[NSMutableArray alloc] init];

      // Retrieve just the fat_header, if possible.
      NSData *head = [self safeSubdataWithRange:NSMakeRange(0, sizeof(struct fat_header))];
      if (!head) return nil;
      struct fat_header *fat_header = (struct fat_header *)[head bytes];

      // Get number of architectures in the binary
      uint32_t narch = NSSwapBigIntToHost(fat_header->nfat_arch);

      // Retrieve just the fat_arch's, make a mutable copy and if necessary swap the bytes
      NSData *archs = [self safeSubdataWithRange:NSMakeRange(sizeof(struct fat_header),
                                                             sizeof(struct fat_arch) * narch)];
      if (!archs) return nil;
      struct fat_arch *fat_archs = (struct fat_arch *)[archs bytes];

      // For each arch, get the name of its architecture
      for (uint32_t i = 0; i < narch; ++i) {
        cpu_type_t cpu = (cpu_type_t)NSSwapBigIntToHost((unsigned int)fat_archs[i].cputype);
        [ret addObject:[self nameForCPUType:cpu]];
      }

      self.architecturesArray = ret;
    } else if ([self firstMachHeader]) {
      struct mach_header *hdr = [self firstMachHeader];
      self.architecturesArray = @[ [self nameForCPUType:hdr->cputype] ];
    }
  }

  return self.architecturesArray == (NSArray *)[NSNull null] ? nil : self.architecturesArray;
}

- (BOOL)isDylib {
  struct mach_header *mach_header = [self firstMachHeader];
  if (mach_header && (mach_header->filetype == MH_DYLIB || mach_header->filetype == MH_FVMLIB)) {
    return YES;
  }

  return NO;
}

- (BOOL)isKext {
  struct mach_header *mach_header = [self firstMachHeader];
  if (mach_header && mach_header->filetype == MH_KEXT_BUNDLE) {
    return YES;
  }

  return NO;
}

- (BOOL)isMachO {
  return [self firstMachHeader] != nil;
}

- (BOOL)isFat {
  return ([self isFatHeader:(struct fat_header *)[self.fileData bytes]]);
}

- (BOOL)isScript {
  char magic[2];
  [self.fileData getBytes:&magic length:2];

  return (strncmp("#!", magic, 2) == 0);
}

- (BOOL)isExecutable {
  struct mach_header *mach_header = [self firstMachHeader];
  if (!mach_header) return NO;
  if (mach_header->filetype == MH_OBJECT ||
      mach_header->filetype == MH_EXECUTE ||
      mach_header->filetype == MH_PRELOAD) {
    return YES;
  }

  return NO;
}

#pragma mark Bundle Information

///
///  Try and determine the bundle that the represented executable is contained within, if any.
///
///  Rationale: An NSBundle has a method executablePath for discovering the main binary within a
///  bundle but provides no way to get an NSBundle object when only the executablePath is known.
///  Also a bundle can contain multiple binaries within the MacOS folder and we want any of these
///  to count as being part of the bundle.
///
///  This method relies on executable bundles being laid out as follows:
///
/// @code
/// Bundle.app/
///    Contents/
///       MacOS/
///         executable
/// @endcode
///
///  If @c self.path is the full path to @c executable above, this method would return an
///  NSBundle reference for Bundle.app.
///
- (NSBundle *)bundle {
  if (!self.bundleRef) {
    self.bundleRef = (NSBundle *)[NSNull null];

    // Check that the full path is at least 4-levels deep:
    // e.g: /Calendar.app/Contents/MacOS/Calendar
    NSArray *pathComponents = [self.path pathComponents];
    if ([pathComponents count] < 4) return nil;

    pathComponents = [pathComponents subarrayWithRange:NSMakeRange(0, [pathComponents count] - 3)];
    NSBundle *bndl = [NSBundle bundleWithPath:[NSString pathWithComponents:pathComponents]];
    if (bndl && [bndl objectForInfoDictionaryKey:@"CFBundleIdentifier"]) self.bundleRef = bndl;
  }
  return self.bundleRef == (NSBundle *)[NSNull null] ? nil : self.bundleRef;
}

- (NSString *)bundlePath {
  return [self.bundle bundlePath];
}

- (NSDictionary *)infoPlist {
  if (!self.infoDict) {
    self.infoDict = (NSDictionary *)[NSNull null];

    if ([self bundle] && [self.bundle infoDictionary]) {
      self.infoDict = [self.bundle infoDictionary];
    } else {
      // Binaries with embedded Info.plist aren't in an NSBundle but
      // CFBundleCopyInfoDictionaryForURL will return the embedded info dict.
      NSURL *url = [NSURL fileURLWithPath:self.path isDirectory:NO];
      NSDictionary *infoDict =
      (__bridge_transfer NSDictionary *)CFBundleCopyInfoDictionaryForURL((__bridge CFURLRef)url);
      if (infoDict) self.infoDict = infoDict;
    }
  }
  return self.infoDict == (NSDictionary *)[NSNull null] ? nil : self.infoDict;
}

- (NSString *)bundleIdentifier {
  return [self.infoPlist objectForKey:@"CFBundleIdentifier"];
}

- (NSString *)bundleName {
  return [self.infoPlist objectForKey:@"CFBundleName"];
}

- (NSString *)bundleVersion {
  return [self.infoPlist objectForKey:@"CFBundleVersion"];
}

- (NSString *)bundleShortVersionString {
  return [self.infoPlist objectForKey:@"CFBundleShortVersionString"];
}

- (NSArray *)downloadURLs {
  char *path = (char *)[self.path fileSystemRepresentation];
  size_t size = (size_t)getxattr(path, "com.apple.metadata:kMDItemWhereFroms", NULL, 0, 0, 0);
  char *value = malloc(size);
  if (!value) return nil;

  if (getxattr(path, "com.apple.metadata:kMDItemWhereFroms", value, size, 0, 0) == -1) {
    free(value);
    return nil;
  }

  NSData *data = [NSData dataWithBytes:value length:size];
  free(value);

  if (data) {
    NSArray *urls = [NSPropertyListSerialization propertyListWithData:data
                                                              options:NSPropertyListImmutable
                                                               format:NULL
                                                                error:NULL];
    return urls;
  }

  return nil;
}

#pragma mark Internal Methods

///
///  Look through the file for the first mach_header. If the file is thin, this will be the
///  header at the beginning of the file. If the file is fat, it will be the first
///  architecture-specific header.
///
- (struct mach_header *)firstMachHeader {
  if (!self.firstMachHeaderData) {
    self.firstMachHeaderData = (NSData *)[NSNull null];

    if ([self isFatHeader:(struct fat_header *)[self.fileData bytes]]) {
      // Get the bytes for the fat_arch
      NSData *archHdr = [self safeSubdataWithRange:NSMakeRange(sizeof(struct fat_header),
                                                               sizeof(struct fat_arch))];
      if (!archHdr) return NULL;
      struct fat_arch *fat_arch = (struct fat_arch *)[archHdr bytes];

      // Get bytes for first mach_header
      NSData *machHdr = [self safeSubdataWithRange:NSMakeRange(NSSwapBigIntToHost(fat_arch->offset),
                                                               sizeof(struct mach_header))];
      if (!machHdr || ![self isMachHeader:(struct mach_header *)machHdr.bytes]) return NULL;

      self.firstMachHeaderData = [machHdr copy];
    } else if ([self isMachHeader:(struct mach_header *)[self.fileData bytes]]) {
      NSData *machHdr = [self safeSubdataWithRange:NSMakeRange(0, sizeof(struct mach_header))];
      if (!machHdr) return NULL;
      self.firstMachHeaderData = [machHdr copy];
    }
  }
  return (self.firstMachHeaderData == (NSData *)[NSNull null] ?
          NULL :
          (struct mach_header *)self.firstMachHeaderData.bytes);
}

- (BOOL)isMachHeader:(struct mach_header *)header {
  return (header->magic == MH_MAGIC || header->magic == MH_MAGIC_64 ||
          header->magic == MH_CIGAM || header->magic == MH_CIGAM_64);
}

- (BOOL)isFatHeader:(struct fat_header *)header {
  return (header->magic == FAT_MAGIC || header->magic == FAT_CIGAM);
}

///
///  Wrap @c subdataWithRange: in a @@try/@@catch, returning nil on exception.
///  Useful for when the range is beyond the end of the file.
///
- (NSData *)safeSubdataWithRange:(NSRange)range {
  @try {
    return [self.fileData subdataWithRange:range];
  }
  @catch (NSException *e) {
    return nil;
  }
}

- (NSString *)nameForCPUType:(cpu_type_t)cpuType {
  switch (cpuType) {
    case CPU_TYPE_X86:
      return @"i386";
    case CPU_TYPE_X86_64:
      return @"x86-64";
    case CPU_TYPE_POWERPC:
      return @"ppc";
    case CPU_TYPE_POWERPC64:
      return @"ppc64";
    default:
      return @"unknown";
  }
  return nil;
}

- (NSString *)resolvePath:(NSString *)path {
  // Convert to absolute, standardized path
  path = [path stringByResolvingSymlinksInPath];
  if (![path isAbsolutePath]) {
    NSString *cwd = [[NSFileManager defaultManager] currentDirectoryPath];
    path = [cwd stringByAppendingPathComponent:path];
  }
  path = [path stringByStandardizingPath];

  // Determine if file exists.
  // If path is actually a directory, check to see if it's a bundle and has a CFBundleExecutable.
  BOOL directory;
  if (![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&directory]) {
    return nil;
  } else if (directory) {
    NSString *infoPath = [path stringByAppendingPathComponent:@"Contents/Info.plist"];
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:infoPath];
    if (d && d[@"CFBundleExecutable"]) {
      path = [path stringByAppendingPathComponent:@"Contents/MacOS"];
      return [path stringByAppendingPathComponent:d[@"CFBundleExecutable"]];
    } else {
      return nil;
    }
  } else {
    return path;
  }
}

@end
