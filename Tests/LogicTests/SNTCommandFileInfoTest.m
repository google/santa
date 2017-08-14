/// Copyright 2016 Google Inc. All rights reserved.
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

@import XCTest;

#import <OCMock/OCMock.h>

#import "MOLCodesignChecker.h"
#import "SNTFileInfo.h"
#import "SNTXPCConnection.h"

@interface SNTCommandFileInfo : NSObject

typedef id (^SNTAttributeBlock)(SNTCommandFileInfo *, SNTFileInfo *);
@property(nonatomic) BOOL recursive;
@property(nonatomic) BOOL jsonOutput;
@property(nonatomic) NSNumber *certIndex;
@property(nonatomic, copy) NSArray<NSString *> *outputKeyList;
@property(nonatomic) NSDictionary<NSString *, SNTAttributeBlock> *propertyMap;
+ (NSArray *)fileInfoKeys;
+ (NSArray *)signingChainKeys;
- (SNTAttributeBlock)codeSigned;
- (instancetype)initWithDaemonConnection:(SNTXPCConnection *)daemonConn;
- (NSArray *)parseArguments:(NSArray *)arguments;

@end

@interface SNTCommandFileInfoTest : XCTestCase

@property SNTCommandFileInfo *cfi;
@property SNTFileInfo *fileInfo;
@property id cscMock;

@end

@implementation SNTCommandFileInfoTest

- (void)setUp {
  [super setUp];

  self.cfi = [[SNTCommandFileInfo alloc] initWithDaemonConnection:nil];
  self.fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:@"/usr/bin/yes" error:nil];
  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);
}

- (void)tearDown {
  self.cfi = nil;
  self.fileInfo = nil;
  [self.cscMock stopMocking];
  self.cscMock = nil;

  [super tearDown];
}

- (void)testParseArgumentsKey {
  NSArray *filePaths = [self.cfi parseArguments:@[ @"--key", @"SHA-256", @"/usr/bin/yes" ]];
  XCTAssertTrue([self.cfi.outputKeyList containsObject:@"SHA-256"]);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsCertIndex {
  NSArray *filePaths = [self.cfi parseArguments:@[ @"--cert-index", @"1", @"/usr/bin/yes" ]];
  XCTAssertEqualObjects(self.cfi.certIndex, @(1));
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsJSONFalse {
  NSArray *filePaths = [self.cfi parseArguments:@[ @"/usr/bin/yes" ]];
  XCTAssertFalse(self.cfi.jsonOutput);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsJSONFalseWithPath {
  NSArray *filePaths = [self.cfi parseArguments:@[ @"/usr/bin/yes", @"json" ]];
  XCTAssertFalse(self.cfi.jsonOutput);
  XCTAssertTrue([filePaths containsObject:@"json"]);
}

- (void)testParseArgumentsJSONTrue {
  NSArray *filePaths = [self.cfi parseArguments:@[ @"--json", @"/usr/bin/yes" ]];
  XCTAssertTrue(self.cfi.jsonOutput);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
}

- (void)testParseArgumentsFilePaths {
  NSArray *args = @[ @"/usr/bin/yes", @"/bin/mv", @"--key", @"SHA-256", @"/bin/ls", @"--json",
                     @"/bin/rm", @"--cert-index", @"1", @"/bin/cp" ];
  NSArray *filePaths = [self.cfi parseArguments:args];
  XCTAssertEqual(filePaths.count, 5);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/mv"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/ls"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/rm"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/cp"]);
}

- (void)testParseArgumentsFilePathSameAsKey {
  NSArray *filePaths = [self.cfi parseArguments:@[ @"--key", @"Rule", @"Rule"]];
  XCTAssertTrue([self.cfi.outputKeyList containsObject:@"Rule"]);
  XCTAssertEqual(filePaths.count, 1);
  XCTAssertTrue([filePaths containsObject:@"Rule"]);
}

- (void)testKeysAlignWithPropertyMap {
  NSArray *mapKeys = self.cfi.propertyMap.allKeys;
  NSArray *fileInfokeys = [SNTCommandFileInfo fileInfoKeys];
  for (NSString *key in fileInfokeys) XCTAssertTrue([mapKeys containsObject:key]);
  for (NSString *key in mapKeys) XCTAssertTrue([fileInfokeys containsObject:key]);
}

- (void)testCodeSignedNo {
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSUnsigned userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), @"No");
}

- (void)testCodeSignedSignatureFailed {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedStaticCodeChanged {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSStaticCodeChanged userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedSignatureNotVerifiable {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureNotVerifiable userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedSignatureUnsupported {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureUnsupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourceDirectoryFailed {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourceDirectoryFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourceNotSupported {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourceNotSupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourceRulesInvalid {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourceRulesInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourcesInvalid {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourcesInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourcesNotFound {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourcesNotFound userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedResourcesNotSealed {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourcesNotSealed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedReqFailed {
  NSString *expected = @"Yes, but failed requirement validation";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSReqFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedReqInvalid {
  NSString *expected = @"Yes, but failed requirement validation";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSReqInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedReqUnsupported {
  NSString *expected = @"Yes, but failed requirement validation";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSReqUnsupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedInfoPlistFailed {
  NSString *expected = @"Yes, but can't validate as Info.plist is missing";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSInfoPlistFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

- (void)testCodeSignedDefault {
  NSString *expected = @"Yes, but failed to validate (999)";
  NSError *err = [NSError errorWithDomain:@"" code:999 userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi, self.fileInfo), expected);
}

@end
