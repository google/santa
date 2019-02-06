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

#import <XCTest/XCTest.h>

#import "Source/common/SNTFileInfo.h"

@interface SNTFileInfoTest : XCTestCase
@end

@implementation SNTFileInfoTest

- (NSString *)directoryBundle {
  NSString *rp = [[NSBundle bundleForClass:[self class]] resourcePath];
  return [rp stringByAppendingPathComponent:@"testdata/DirectoryBundle"];
}

- (NSString *)bundleExample {
  NSString *rp = [[NSBundle bundleForClass:[self class]] resourcePath];
  return [rp stringByAppendingPathComponent:@"testdata/BundleExample.app"];
}

- (void)testPathStandardizing {
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:@"/Applications/Safari.app"];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.path, @"/Applications/Safari.app/Contents/MacOS/Safari");

  sut = [[SNTFileInfo alloc] initWithPath:@"../../../../../../../../../../../../../../../bin/ls"];
  XCTAssertEqualObjects(sut.path, @"/bin/ls");

  sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/qlmanage"];
  XCTAssertEqualObjects(sut.path, @"/System/Library/Frameworks/QuickLook.framework/Versions/A/"
                                  @"Resources/quicklookd.app/Contents/MacOS/qlmanage");
}

- (void)testSHA1 {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"missing_pagezero"
                                                                    ofType:@""];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil(sut.SHA1);
  XCTAssertEqual(sut.SHA1.length, 40);
  XCTAssertEqualObjects(sut.SHA1, @"3a865bf47b4ceba20496e0e66e39e4cfa101ffe6");
}

- (void)testSHA256 {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"missing_pagezero"
                                                                    ofType:@""];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil(sut.SHA256);
  XCTAssertEqual(sut.SHA256.length, 64);
  XCTAssertEqualObjects(sut.SHA256,
                        @"5e089b65a1e7a4696d84a34510710b6993d1de21250c41daaec63d9981083eba");
}

- (void)testExecutable {
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:@"/sbin/launchd"];

  XCTAssertTrue(sut.isMachO);
  XCTAssertTrue(sut.isExecutable);

  XCTAssertFalse(sut.isDylib);
  XCTAssertFalse(sut.isFat);
  XCTAssertFalse(sut.isKext);
  XCTAssertFalse(sut.isScript);
}

- (void)testPageZero {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"missing_pagezero"
                                                                    ofType:@""];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertTrue(sut.isMissingPageZero);

  path = [[NSBundle bundleForClass:[self class]] pathForResource:@"bad_pagezero" ofType:@""];
  sut = [[SNTFileInfo alloc] initWithPath:path];
  XCTAssertTrue(sut.isMissingPageZero);

  sut = [[SNTFileInfo alloc] initWithPath:@"/usr/sbin/bless"];
  XCTAssertFalse(sut.isMissingPageZero);
}

- (void)testKext {
  SNTFileInfo *sut =
      [[SNTFileInfo alloc] initWithPath:
          @"/System/Library/Extensions/AppleAPIC.kext/Contents/MacOS/AppleAPIC"];

  XCTAssertTrue(sut.isMachO);
  XCTAssertTrue(sut.isKext);

  XCTAssertFalse(sut.isDylib);
  XCTAssertFalse(sut.isExecutable);
  XCTAssertFalse(sut.isFat);
  XCTAssertFalse(sut.isScript);
}

- (void)testDylibs {
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:@"/usr/lib/libsqlite3.dylib"];

  XCTAssertTrue(sut.isMachO);
  XCTAssertTrue(sut.isDylib);
  XCTAssertTrue(sut.isFat);

  XCTAssertFalse(sut.isKext);
  XCTAssertFalse(sut.isExecutable);
  XCTAssertFalse(sut.isScript);
}

- (void)testScript {
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/h2ph"];

  XCTAssertTrue(sut.isScript);

  XCTAssertFalse(sut.isDylib);
  XCTAssertFalse(sut.isExecutable);
  XCTAssertFalse(sut.isFat);
  XCTAssertFalse(sut.isKext);
  XCTAssertFalse(sut.isMachO);
}

- (void)testBundle {
  NSString *path = [self bundleExample];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.google.santa.BundleExample");
  XCTAssertEqualObjects([sut bundleName], @"BundleExample");
  XCTAssertEqualObjects([sut bundleVersion], @"1");
  XCTAssertEqualObjects([sut bundleShortVersionString], @"1.0");
  XCTAssertEqualObjects([sut bundlePath], path);
}

- (void)testAncestorBundle {
  NSString *path = [self bundleExample];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];
  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.google.santa.UnitTest.SNTFileInfoTest");
  XCTAssertNotNil([sut bundleVersion]);
  XCTAssertNotNil([sut bundleShortVersionString]);

  NSString *ancestorBundlePath = path;
  for (int i = 0; i < 4; i++) {
    ancestorBundlePath = [ancestorBundlePath stringByDeletingLastPathComponent];
  }
  XCTAssertEqualObjects([sut bundlePath], ancestorBundlePath);
}

- (void)testBundleIsAncestor {
  NSString *path = [NSBundle bundleForClass:[self class]].bundlePath;
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];
  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.google.santa.UnitTest.SNTFileInfoTest");
  XCTAssertNotNil([sut bundleVersion]);
  XCTAssertNotNil([sut bundleShortVersionString]);
  XCTAssertEqualObjects([sut bundlePath], path);
}

- (void)testDirectoryBundleIsNotAncestor {
  NSString *path = [self directoryBundle];
  NSString *directoryBundle = @"/tmp/DirectoryBundle";
  NSFileManager *fm = [NSFileManager defaultManager];
  [fm removeItemAtPath:directoryBundle error:NULL];
  [fm copyItemAtPath:path toPath:directoryBundle error:NULL];
  path = [directoryBundle stringByAppendingString:@"/Contents/Resources/BundleExample.app"];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];
  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.google.santa.BundleExample");
  XCTAssertEqualObjects([sut bundleName], @"BundleExample");
  XCTAssertEqualObjects([sut bundleVersion], @"1");
  XCTAssertEqualObjects([sut bundleShortVersionString], @"1.0");
  XCTAssertEqualObjects([sut bundlePath], path);
}

- (void)testBundleCacheReset {
  NSString *path = [self bundleExample];
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:path];

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.google.santa.BundleExample");
  XCTAssertEqualObjects([sut bundleName], @"BundleExample");
  XCTAssertEqualObjects([sut bundleVersion], @"1");
  XCTAssertEqualObjects([sut bundleShortVersionString], @"1.0");
  XCTAssertEqualObjects([sut bundlePath], path);

  sut.useAncestorBundle = YES;

  XCTAssertNotNil([sut bundle]);

  XCTAssertEqualObjects([sut bundleIdentifier], @"com.google.santa.UnitTest.SNTFileInfoTest");
  XCTAssertNotNil([sut bundleVersion]);
  XCTAssertNotNil([sut bundleShortVersionString]);

  NSString *ancestorBundlePath = path;
  for (int i = 0; i < 4; i++) {
    ancestorBundlePath = [ancestorBundlePath stringByDeletingLastPathComponent];
  }
  XCTAssertEqualObjects([sut bundlePath], ancestorBundlePath);
}

- (void)testNonBundle {
  SNTFileInfo *sut =
  [[SNTFileInfo alloc] initWithPath:@"/usr/bin/yes"];

  XCTAssertNil([sut bundle]);

  sut.useAncestorBundle = YES;

  XCTAssertNil([sut bundle]);
}

- (void)testEmbeddedInfoPlist {
  // csreq is installed on all machines with Xcode installed. If you're running these tests,
  // it should be available..
  SNTFileInfo *sut = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/csreq"];

  XCTAssertNotNil([sut infoPlist]);
}

@end
