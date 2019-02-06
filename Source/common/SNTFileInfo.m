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

#import "Source/common/SNTFileInfo.h"

#import <CommonCrypto/CommonDigest.h>
#import <fmdb/FMDB.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/xattr.h>


// Simple class to hold the data of a mach_header and the offset within the file
// in which that header was found.
@interface MachHeaderWithOffset : NSObject
@property NSData *data;
@property uint32_t offset;
- (instancetype)initWithData:(NSData *)data offset:(uint32_t)offset;
@end
@implementation MachHeaderWithOffset
- (instancetype)initWithData:(NSData *)data offset:(uint32_t)offset {
  self = [super init];
  if (self) {
    _data = data;
    _offset = offset;
  }
  return self;
}
@end

@interface SNTFileInfo ()
@property NSString *path;
@property NSFileHandle *fileHandle;
@property NSUInteger fileSize;
@property NSString *fileOwnerHomeDir;

// Cached properties
@property NSBundle *bundleRef;
@property NSDictionary *infoDict;
@property NSDictionary *quarantineDict;
@property NSDictionary *cachedHeaders;
@property MOLCodesignChecker *cachedCodesignChecker;
@property(nonatomic) NSError *codesignCheckerError;
@end

@implementation SNTFileInfo

extern NSString *const NSURLQuarantinePropertiesKey WEAK_IMPORT_ATTRIBUTE;

- (instancetype)initWithResolvedPath:(NSString *)path error:(NSError **)error {
  self = [super init];
  if (self) {
    _path = path;
    if (!_path.length) {
      if (error) {
        NSString *errStr = @"Unable to use empty path";
        *error = [NSError errorWithDomain:@"com.google.santa.fileinfo"
                                     code:270
                                 userInfo:@{NSLocalizedDescriptionKey : errStr}];
      }
      return nil;
    }

    struct stat fileStat;
    lstat(_path.UTF8String, &fileStat);
    if (!((S_IFMT & fileStat.st_mode) == S_IFREG)) {
      if (error) {
        NSString *errStr = [NSString stringWithFormat:@"Non regular file: %s", strerror(errno)];
        *error = [NSError errorWithDomain:@"com.google.santa.fileinfo"
                                     code:290
                                 userInfo:@{NSLocalizedDescriptionKey : errStr}];
      }
      return nil;
    }

    _fileSize = fileStat.st_size;

    if (_fileSize == 0) return nil;

    if (fileStat.st_uid != 0) {
      struct passwd *pwd = getpwuid(fileStat.st_uid);
      if (pwd) {
        _fileOwnerHomeDir = @(pwd->pw_dir);
      }
    }

    int fd = open([_path UTF8String], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      if (error) {
        NSString *errStr = [NSString stringWithFormat:@"Unable to open file: %s", strerror(errno)];
        *error = [NSError errorWithDomain:@"com.google.santa.fileinfo"
                                     code:280
                                 userInfo:@{NSLocalizedDescriptionKey : errStr}];
      }
      return nil;
    }
    _fileHandle = [[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES];
  }

  return self;
}

- (instancetype)initWithPath:(NSString *)path error:(NSError **)error {
  NSBundle *bndl;
  NSString *resolvedPath = [self resolvePath:path bundle:&bndl];
  if (!resolvedPath.length) {
    if (error) {
      NSString *errStr = @"Unable to resolve empty path";
      if (path) errStr = [@"Unable to resolve path: " stringByAppendingString:path];
      *error = [NSError errorWithDomain:@"com.google.santa.fileinfo"
                                   code:260
                               userInfo:@{NSLocalizedDescriptionKey : errStr}];
    }
    return nil;
  }
  self = [self initWithResolvedPath:resolvedPath error:error];
  if (self && bndl) _bundleRef = bndl;
  return self;
}

- (instancetype)initWithPath:(NSString *)path {
  return [self initWithPath:path error:NULL];
}

#pragma mark Hashing

- (void)hashSHA1:(NSString **)sha1 SHA256:(NSString **)sha256 {
  const int MAX_CHUNK_SIZE = 256 * 1024;  // 256 KB
  const size_t chunkSize = _fileSize > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : _fileSize;
  char chunk[chunkSize];

  CC_SHA1_CTX c1;
  CC_SHA256_CTX c256;

  if (sha1) CC_SHA1_Init(&c1);
  if (sha256) CC_SHA256_Init(&c256);

  int fd = self.fileHandle.fileDescriptor;

  fcntl(fd, F_RDAHEAD, 1);
  struct radvisory radv;
  radv.ra_offset = 0;
  const int MAX_ADVISORY_READ = 10 * 1024 * 1024;
  radv.ra_count = (int)_fileSize < MAX_ADVISORY_READ ? (int)_fileSize : MAX_ADVISORY_READ;
  fcntl(fd, F_RDADVISE, &radv);
  ssize_t bytesRead;

  for (uint64_t offset = 0; offset < _fileSize;) {
    bytesRead = pread(fd, chunk, chunkSize, offset);
    if (bytesRead > 0) {
      if (sha1) CC_SHA1_Update(&c1, chunk, (CC_LONG)bytesRead);
      if (sha256) CC_SHA256_Update(&c256, chunk, (CC_LONG)bytesRead);
      offset += bytesRead;
    } else if (bytesRead == -1 && errno == EINTR) {
      continue;
    } else {
      return;
    }
  }

  // We turn off Read Ahead that we turned on
  fcntl(fd, F_RDAHEAD, 0);
  if (sha1) {
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1_Final(digest, &c1);
    NSString *const SHA1FormatString =
        @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";
    *sha1 = [[NSString alloc]
        initWithFormat:SHA1FormatString, digest[0], digest[1], digest[2],
                       digest[3], digest[4], digest[5], digest[6], digest[7],
                       digest[8], digest[9], digest[10], digest[11], digest[12],
                       digest[13], digest[14], digest[15], digest[16],
                       digest[17], digest[18], digest[19]];
  }
  if (sha256) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &c256);
    NSString *const SHA256FormatString =
        @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
         "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

    *sha256 = [[NSString alloc]
        initWithFormat:SHA256FormatString, digest[0], digest[1], digest[2],
                       digest[3], digest[4], digest[5], digest[6], digest[7],
                       digest[8], digest[9], digest[10], digest[11], digest[12],
                       digest[13], digest[14], digest[15], digest[16],
                       digest[17], digest[18], digest[19], digest[20],
                       digest[21], digest[22], digest[23], digest[24],
                       digest[25], digest[26], digest[27], digest[28],
                       digest[29], digest[30], digest[31]];
  }
}

- (NSString *)SHA1 {
  NSString *sha1;
  [self hashSHA1:&sha1 SHA256:NULL];
  return sha1;
}

- (NSString *)SHA256 {
  NSString *sha256;
  [self hashSHA1:NULL SHA256:&sha256];
  return sha256;
}

#pragma mark File Type Info

- (NSArray *)architectures {
  return [self.machHeaders allKeys];
}

- (uint32_t)machFileType {
  struct mach_header *mach_header = [self firstMachHeader];
  if (mach_header) return mach_header->filetype;
  return -1;
}

- (BOOL)isExecutable {
  return [self machFileType] == MH_EXECUTE;
}

- (BOOL)isDylib {
  return [self machFileType] == MH_DYLIB;
}

- (BOOL)isBundle {
  return [self machFileType] == MH_BUNDLE;
}

- (BOOL)isKext {
  return [self machFileType] == MH_KEXT_BUNDLE;
}

- (BOOL)isMachO {
  return (self.machHeaders.count > 0);
}

- (BOOL)isFat {
  return (self.machHeaders.count > 1);
}

- (BOOL)isScript {
  const char *magic = (const char *)[[self safeSubdataWithRange:NSMakeRange(0, 2)] bytes];
  return (magic && memcmp("#!", magic, 2) == 0);
}

- (BOOL)isXARArchive {
  const char *magic = (const char *)[[self safeSubdataWithRange:NSMakeRange(0, 4)] bytes];
  return (magic && memcmp("xar!", magic, 4) == 0);
}

- (BOOL)isDMG {
  if (self.fileSize < 512) return NO;
  NSUInteger last512 = self.fileSize - 512;
  const char *magic = (const char *)[[self safeSubdataWithRange:NSMakeRange(last512, 4)] bytes];
  return (magic && memcmp("koly", magic, 4) == 0);
}

- (NSString *)humanReadableFileType {
  if ([self isExecutable]) return @"Executable";
  if ([self isDylib]) return @"Dynamic Library";
  if ([self isBundle]) return @"Bundle/Plugin";
  if ([self isKext]) return @"Kernel Extension";
  if ([self isScript]) return @"Script";
  if ([self isXARArchive]) return @"XAR Archive";
  if ([self isDMG]) return @"Disk Image";
  return @"Unknown";
}

#pragma mark Page Zero

- (BOOL)isMissingPageZero {
  // This method only checks i386 arch because the kernel enforces this for other archs
  // See bsd/kern/mach_loader.c, search for enforce_hard_pagezero.
  MachHeaderWithOffset *x86Header = self.machHeaders[[self nameForCPUType:CPU_TYPE_X86
                                                               cpuSubType:CPU_SUBTYPE_I386_ALL]];
  if (!x86Header) return NO;

  struct mach_header *mh = (struct mach_header *)[x86Header.data bytes];
  if (mh->filetype != MH_EXECUTE) return NO;

  NSRange range = NSMakeRange(x86Header.offset + sizeof(struct mach_header),
                              sizeof(struct segment_command));
  NSData *lcData = [self safeSubdataWithRange:range];
  if (!lcData) return NO;

  // This code assumes the __PAGEZERO is always the first load-command in the file.
  // Given that the macOS ABI says "the static linker creates a __PAGEZERO segment
  // as the first segment of an executable file." this should be OK.
  struct load_command *lc = (struct load_command *)[lcData bytes];
  if (lc->cmd == LC_SEGMENT) {
    struct segment_command *segment = (struct segment_command *)lc;
    if (segment->vmaddr == 0 && segment->vmsize != 0 &&
        segment->initprot == 0 && segment->maxprot == 0 &&
        strcmp("__PAGEZERO", segment->segname) == 0) {
      return NO;
    }
  }
  return YES;
}

#pragma mark Bundle Information

///
///  Directories with a "Contents/Info.plist" entry can be mistaken as a bundle. To be considered an
///  ancestor, the bundle must have a valid extension.
///
- (NSSet *)allowedAncestorExtensions {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [NSSet setWithArray:@[
      @"app",
      @"bundle",
      @"framework",
      @"kext",
      @"xctest",
      @"xpc",
    ]];
  });
  return set;
}

///
///  Try and determine the bundle that the represented executable is contained within, if any.
///
///  Rationale: An NSBundle has a method executablePath for discovering the main binary within a
///  bundle but provides no way to get an NSBundle object when only the executablePath is known.
///  Also a bundle can contain multiple binaries within its subdirectories and we want any of these
///  to count as being part of the bundle.
///
///  This method walks up the path until a bundle is found, if any.
///
///  @param ancestor YES this will return the highest NSBundle, with a valid extension, found in the
///                  tree. NO will return the the lowest NSBundle, without validating the extension.
///
- (NSBundle *)findBundleWithAncestor:(BOOL)ancestor {
  NSBundle *bundle;
  NSMutableArray *pathComponents = [[self.path pathComponents] mutableCopy];

  // Ignore the root path "/", for some reason this is considered a bundle.
  while (pathComponents.count > 1) {
    NSBundle *bndl = [NSBundle bundleWithPath:[NSString pathWithComponents:pathComponents]];
    if ([bndl objectForInfoDictionaryKey:@"CFBundleIdentifier"]) {
      if (!ancestor ||
          [[self allowedAncestorExtensions] containsObject:bndl.bundlePath.pathExtension]) {
        bundle = bndl;
      }
      if (!ancestor) break;
    }
    [pathComponents removeLastObject];
  }
  return bundle;
}

- (NSBundle *)bundle {
  if (!self.bundleRef) {
    self.bundleRef =
        [self findBundleWithAncestor:self.useAncestorBundle] ?: (NSBundle *)[NSNull null];
  }
  return self.bundleRef == (NSBundle *)[NSNull null] ? nil : self.bundleRef;
}

- (NSString *)bundlePath {
  return [self.bundle bundlePath];
}

- (void)setUseAncestorBundle:(BOOL)useAncestorBundle {
  if (self.useAncestorBundle != useAncestorBundle) {
    self.bundleRef = nil;
    self.infoDict = nil;
  }
  _useAncestorBundle = useAncestorBundle;
}

- (NSDictionary *)infoPlist {
  if (!self.infoDict) {
    NSDictionary *d = [self embeddedPlist];
    if (d) {
      self.infoDict = d;
      return self.infoDict;
    }

    d = self.bundle.infoDictionary;
    if (d) {
      self.infoDict = d;
      return self.infoDict;
    }

    self.infoDict = (NSDictionary *)[NSNull null];
  }
  return self.infoDict == (NSDictionary *)[NSNull null] ? nil : self.infoDict;
}

- (NSString *)bundleIdentifier {
  return [[self.infoPlist objectForKey:@"CFBundleIdentifier"] description];
}

- (NSString *)bundleName {
  return [[self.infoPlist objectForKey:@"CFBundleDisplayName"] description] ?:
         [[self.infoPlist objectForKey:@"CFBundleName"] description];
}

- (NSString *)bundleVersion {
  return [[self.infoPlist objectForKey:@"CFBundleVersion"] description];
}

- (NSString *)bundleShortVersionString {
  return [[self.infoPlist objectForKey:@"CFBundleShortVersionString"] description];
}

#pragma mark Quarantine Data

- (NSString *)quarantineDataURL {
  NSURL *dataURL = [self quarantineData][@"LSQuarantineDataURL"];
  if (dataURL == (NSURL *)[NSNull null]) dataURL = nil;
  return [dataURL absoluteString];
}

- (NSString *)quarantineRefererURL {
  NSURL *originURL = [self quarantineData][@"LSQuarantineOriginURL"];
  if (originURL == (NSURL *)[NSNull null]) originURL = nil;
  return [originURL absoluteString];
}

- (NSString *)quarantineAgentBundleID {
  NSString *agentBundle = [self quarantineData][@"LSQuarantineAgentBundleIdentifier"];
  if (agentBundle == (NSString *)[NSNull null]) agentBundle = nil;
  return agentBundle;
}

- (NSDate *)quarantineTimestamp {
  NSDate *timeStamp = [self quarantineData][@"LSQuarantineTimeStamp"];
  return timeStamp;
}

#pragma mark Internal Methods

- (NSDictionary *)machHeaders {
  if (self.cachedHeaders) return self.cachedHeaders;

  // Sanity check file length
  if (self.fileSize < sizeof(struct mach_header)) {
    self.cachedHeaders = [NSDictionary dictionary];
    return self.cachedHeaders;
  }

  NSMutableDictionary *machHeaders = [NSMutableDictionary dictionary];

  NSData *machHeader = [self parseSingleMachHeader:[self safeSubdataWithRange:NSMakeRange(0,
                                                                                          4096)]];
  if (machHeader) {
    struct mach_header *mh = (struct mach_header *)[machHeader bytes];
    MachHeaderWithOffset *mhwo = [[MachHeaderWithOffset alloc] initWithData:machHeader offset:0];
    machHeaders[[self nameForCPUType:mh->cputype cpuSubType:mh->cpusubtype]] = mhwo;
  } else {
    NSRange range = NSMakeRange(0, sizeof(struct fat_header));
    NSData *fatHeader = [self safeSubdataWithRange:range];
    struct fat_header *fh = (struct fat_header *)[fatHeader bytes];

    if (fatHeader && (fh->magic == FAT_CIGAM || fh->magic == FAT_MAGIC)) {
      int nfat_arch = OSSwapBigToHostInt32(fh->nfat_arch);
      range = NSMakeRange(sizeof(struct fat_header), sizeof(struct fat_arch) * nfat_arch);
      NSMutableData *fatArchs = [[self safeSubdataWithRange:range] mutableCopy];
      if (fatArchs) {
        struct fat_arch *fat_arch = (struct fat_arch *)[fatArchs mutableBytes];
        for (int i = 0; i < nfat_arch; ++i) {
          int offset = OSSwapBigToHostInt32(fat_arch[i].offset);
          int size = OSSwapBigToHostInt32(fat_arch[i].size);
          int cputype = OSSwapBigToHostInt(fat_arch[i].cputype);
          int cpusubtype = OSSwapBigToHostInt(fat_arch[i].cpusubtype);

          range = NSMakeRange(offset, size);
          NSData *machHeader = [self parseSingleMachHeader:[self safeSubdataWithRange:range]];
          if (machHeader) {
            NSString *key = [self nameForCPUType:cputype cpuSubType:cpusubtype];
            MachHeaderWithOffset *mhwo = [[MachHeaderWithOffset alloc] initWithData:machHeader
                                                                             offset:offset];
            machHeaders[key] = mhwo;
          }
        }
      }
    }
  }

  self.cachedHeaders = [machHeaders copy];
  return self.cachedHeaders;
}

- (NSData *)parseSingleMachHeader:(NSData *)inputData {
  if (inputData.length < sizeof(struct mach_header)) return nil;
  struct mach_header *mh = (struct mach_header *)[inputData bytes];

  if (mh->magic == MH_CIGAM || mh->magic == MH_CIGAM_64) {
    NSMutableData *mutableInput = [inputData mutableCopy];
    mh = (struct mach_header *)[mutableInput mutableBytes];
    swap_mach_header(mh, NXHostByteOrder());
  }

  if (mh->magic == MH_MAGIC || mh->magic == MH_MAGIC_64) {
    return [NSData dataWithBytes:mh length:sizeof(struct mach_header)];
  }

  return nil;
}

///
///  Locate an embedded plist in the file
///
- (NSDictionary *)embeddedPlist {
  // Look for an embedded Info.plist if there is one.
  // This could (and used to) use CFBundleCopyInfoDictionaryForURL but that uses mmap to read
  // the file and so can cause SIGBUS if the file is deleted/truncated while it's working.
  MachHeaderWithOffset *mhwo = [[self.machHeaders allValues] firstObject];
  if (!mhwo) return nil;

  struct mach_header *mh = (struct mach_header *)mhwo.data.bytes;
  if (mh->filetype != MH_EXECUTE) return self.infoDict;
  BOOL is64 = (mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64);
  uint32_t ncmds = mh->ncmds;
  uint32_t nsects = 0;
  uint64_t offset = mhwo.offset;

  uint32_t sz_header = is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
  uint32_t sz_segment = is64 ? sizeof(struct segment_command_64) : sizeof(struct segment_command);
  uint32_t sz_section = is64 ? sizeof(struct section_64) : sizeof(struct section);

  offset += sz_header;

  // Loop through the load commands looking for the segment named __TEXT
  for (uint32_t i = 0; i < ncmds; ++i) {
    NSData *cmdData = [self safeSubdataWithRange:NSMakeRange(offset, sz_segment)];
    if (!cmdData) return nil;
    struct segment_command_64 *lc = (struct segment_command_64 *)[cmdData bytes];
    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64) {
      if (memcmp(lc->segname, "__TEXT", 6) == 0) {
        nsects = lc->nsects;
        offset += sz_segment;
        break;
      }
    }
    offset += lc->cmdsize;
  }

  // Loop through the sections in the __TEXT segment looking for an __info_plist section.
  for (uint32_t i = 0; i < nsects; ++i) {
    NSData *sectData = [self safeSubdataWithRange:NSMakeRange(offset, sz_section)];
    if (!sectData) return nil;
    struct section_64 *sect = (struct section_64 *)[sectData bytes];
    if (sect && memcmp(sect->sectname, "__info_plist", 12) == 0 && sect->size < 2000000) {
      NSData *plistData = [self safeSubdataWithRange:NSMakeRange(sect->offset, sect->size)];
      if (!plistData) return nil;
      NSDictionary *plist;
      plist = [NSPropertyListSerialization propertyListWithData:plistData
                                                        options:NSPropertyListImmutable
                                                         format:NULL
                                                          error:NULL];
      if (plist) return plist;
    }
    offset += sz_section;
  }
  return nil;
}

///
///  Return the first mach_header in this file.
///
- (struct mach_header *)firstMachHeader {
  return (struct mach_header *)([[[[self.machHeaders allValues] firstObject] data] bytes]);
}

///
///  Extract a range of the file as an NSData, handling any exceptions.
///  Returns nil if the requested range is outside of the range of the file.
///
- (NSData *)safeSubdataWithRange:(NSRange)range {
  @try {
    if ((range.location + range.length) > self.fileSize) return nil;
    [self.fileHandle seekToFileOffset:range.location];
    NSData *d = [self.fileHandle readDataOfLength:range.length];
    if (d.length != range.length) return nil;
    return d;
  } @catch (NSException *e) {
    return nil;
  }
}

///
///  Retrieve quarantine data for a file and caches the dictionary
///  This method attempts to handle fetching the quarantine data even if the running user
///  is not the one who downloaded the file.
///
- (NSDictionary *)quarantineData {
  if (!self.quarantineDict && self.fileOwnerHomeDir && NSURLQuarantinePropertiesKey) {
    self.quarantineDict = (NSDictionary *)[NSNull null];

    NSURL *url = [NSURL fileURLWithPath:self.path];
    NSDictionary *d = [url resourceValuesForKeys:@[ NSURLQuarantinePropertiesKey ] error:NULL];

    if (d[NSURLQuarantinePropertiesKey]) {
      d = d[NSURLQuarantinePropertiesKey];

      if (d[@"LSQuarantineIsOwnedByCurrentUser"]) {
        self.quarantineDict = d;
      } else if (d[@"LSQuarantineEventIdentifier"]) {
        NSMutableDictionary *quarantineDict = [d mutableCopy];

        // If self.path is on a quarantine disk image, LSQuarantineDiskImageURL will point to the
        // disk image and self.fileOwnerHomeDir will be incorrect (probably root).
        NSString *fileOwnerHomeDir = self.fileOwnerHomeDir;
        if (d[@"LSQuarantineDiskImageURL"]) {
          struct stat fileStat;
          stat([d[@"LSQuarantineDiskImageURL"] fileSystemRepresentation], &fileStat);
          if (fileStat.st_uid != 0) {
            struct passwd *pwd = getpwuid(fileStat.st_uid);
            if (pwd) {
              fileOwnerHomeDir = @(pwd->pw_dir);
            }
          }
        }

        NSURL *dbPath = [NSURL fileURLWithPathComponents:@[
          fileOwnerHomeDir,
          @"Library",
          @"Preferences",
          @"com.apple.LaunchServices.QuarantineEventsV2"
        ]];
        FMDatabase *db = [FMDatabase databaseWithPath:[dbPath absoluteString]];
        db.logsErrors = NO;
        if ([db open]) {
          FMResultSet *rs = [db executeQuery:@"SELECT * FROM LSQuarantineEvent "
                                             @"WHERE LSQuarantineEventIdentifier=?",
                                             d[@"LSQuarantineEventIdentifier"]];
          if ([rs next]) {
            NSString *agentBundleID = [rs stringForColumn:@"LSQuarantineAgentBundleIdentifier"];
            NSString *dataURLString = [rs stringForColumn:@"LSQuarantineDataURLString"];
            NSString *originURLString = [rs stringForColumn:@"LSQuarantineOriginURLString"];
            double timeStamp = [rs doubleForColumn:@"LSQuarantineTimeStamp"];

            quarantineDict[@"LSQuarantineAgentBundleIdentifier"] = agentBundleID;
            quarantineDict[@"LSQuarantineDataURL"] = [NSURL URLWithString:dataURLString];
            quarantineDict[@"LSQuarantineOriginURL"] = [NSURL URLWithString:originURLString];
            quarantineDict[@"LSQuarantineTimestamp"] =
                [NSDate dateWithTimeIntervalSinceReferenceDate:timeStamp];

            self.quarantineDict = quarantineDict;
          }
          [rs close];
          [db close];
        }
      }
    }
  }
  return (self.quarantineDict == (NSDictionary *)[NSNull null]) ? nil : self.quarantineDict;
}

///
///  Return a human-readable string for a cpu_type_t.
///
- (NSString *)nameForCPUType:(cpu_type_t)cpuType cpuSubType:(cpu_subtype_t)cpuSubType {
  const NXArchInfo *archInfo = NXGetArchInfoFromCpuType(cpuType, cpuSubType);
  NSString *arch;
  if (archInfo && archInfo->name) {
    arch = @(archInfo->name);
  } else {
    arch = [NSString stringWithFormat:@"%i:%i", cpuType, cpuSubType];
  }
  return arch;
}

///
///  Resolves a given path:
///    + Follows symlinks
///    + Converts relative paths to absolute
///    + If path is a directory, checks to see if that directory is a bundle and if so
///      returns the path to that bundles CFBundleExecutable and stores a reference to the
///      bundle in the bundle out-param.
///
- (NSString *)resolvePath:(NSString *)path bundle:(NSBundle **)bundle {
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
  } else if (directory && ![path isEqualToString:@"/"]) {
    NSBundle *bndl = [NSBundle bundleWithPath:path];
    if (bundle) *bundle = bndl;
    return [bndl executablePath];
  } else {
    return path;
  }
}

///
///  Cache and return a MOLCodeSignChecker for the given file.  If there was an error creating the
///  code sign checker it will be returned in the passed-in error parameter.
///
- (MOLCodesignChecker *)codesignCheckerWithError:(NSError **)error {
  if (!self.cachedCodesignChecker && !self.codesignCheckerError) {
    NSError *e;
    self.cachedCodesignChecker = [[MOLCodesignChecker alloc] initWithBinaryPath:self.path error:&e];
    self.codesignCheckerError = e;
  }
  if (error) *error = self.codesignCheckerError;
  return self.cachedCodesignChecker;
}

@end
