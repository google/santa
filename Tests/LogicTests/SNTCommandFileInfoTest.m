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
#import "SNTXPCConnection.h"

@interface SNTCommandFileInfo : NSObject

typedef id (^SNTAttributeBlock)(SNTCommandFileInfo *);
@property(nonatomic) NSMutableDictionary *propertyMap;
+ (NSArray *)fileInfoKeys;
+ (NSArray *)signingChainKeys;
- (SNTAttributeBlock)codeSigned;
- (instancetype)initWithFilePath:(NSString *)filePath
                daemonConnection:(SNTXPCConnection *)daemonConn;
+ (void)parseArguments:(NSArray *)args
                forKey:(NSString **)key
             certIndex:(NSNumber **)certIndex
            jsonOutput:(BOOL *)jsonOutput
             filePaths:(NSArray **)filePaths;

@end

@interface SNTCommandFileInfoTest : XCTestCase

@property SNTCommandFileInfo *cfi;
@property id cscMock;

@end

@implementation SNTCommandFileInfoTest

- (void)setUp {
  [super setUp];

  self.cfi = [[SNTCommandFileInfo alloc] initWithFilePath:nil daemonConnection:nil];
  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);
}

- (void)tearDown {
  self.cfi = nil;
  [self.cscMock stopMocking];
  self.cscMock = nil;

  [super tearDown];
}

- (void)testParseArgumentsKey {
  NSString *key;
  NSNumber *certIndex;
  BOOL jsonOutput = NO;
  NSArray *filePaths;
  [SNTCommandFileInfo parseArguments:@[ @"--key", @"SHA-256", @"/usr/bin/yes" ]
                              forKey:&key
                           certIndex:&certIndex
                          jsonOutput:&jsonOutput
                           filePaths:&filePaths];
  XCTAssertEqualObjects(key, @"SHA-256");
}

- (void)testParseArgumentsCertIndex {
  NSString *key;
  NSNumber *certIndex;
  BOOL jsonOutput = NO;
  NSArray *filePaths;
  [SNTCommandFileInfo parseArguments:@[ @"--cert-index", @"1", @"/usr/bin/yes" ]
                              forKey:&key
                           certIndex:&certIndex
                          jsonOutput:&jsonOutput
                           filePaths:&filePaths];
  XCTAssertEqualObjects(certIndex, @(1));
}
- (void)testParseArgumentsJSON {
  NSString *key;
  NSNumber *certIndex;
  BOOL jsonOutput = NO;
  NSArray *filePaths;
  [SNTCommandFileInfo parseArguments:@[ @"--json", @"/usr/bin/yes" ]
                              forKey:&key
                           certIndex:&certIndex
                          jsonOutput:&jsonOutput
                           filePaths:&filePaths];
  XCTAssertTrue(jsonOutput);
}

- (void)testParseArgumentsFilePaths {
  NSString *key;
  NSNumber *certIndex;
  BOOL jsonOutput = NO;
  NSArray *filePaths;
  NSArray *args = @[ @"/usr/bin/yes", @"/bin/mv", @"--key", @"SHA-256", @"/bin/ls", @"--json",
                     @"/bin/rm", @"--cert-index", @"1", @"/bin/cp"];
  [SNTCommandFileInfo parseArguments:args
                              forKey:&key
                           certIndex:&certIndex
                          jsonOutput:&jsonOutput
                           filePaths:&filePaths];
  XCTAssertEqual(filePaths.count, 5);
  XCTAssertTrue([filePaths containsObject:@"/usr/bin/yes"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/mv"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/ls"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/rm"]);
  XCTAssertTrue([filePaths containsObject:@"/bin/cp"]);
}

- (void)testKeysAlignWithPropertyMap {
  NSArray *mapKeys = self.cfi.propertyMap.allKeys;
  NSArray *keys = [SNTCommandFileInfo fileInfoKeys];
  [keys enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    XCTAssertTrue([mapKeys containsObject:obj]);
  }];
  [mapKeys enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    XCTAssertTrue([keys containsObject:obj]);
  }];
}

- (void)testCodeSignedNo {
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSUnsigned userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), @"No");
}

- (void)testCodeSignedSignatureFailed {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedStaticCodeChanged {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSStaticCodeChanged userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedSignatureNotVerifiable {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureNotVerifiable userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedSignatureUnsupported {
  NSString *expected = @"Yes, but code/signature changed/unverifiable";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureUnsupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedResourceDirectoryFailed {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourceDirectoryFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedResourceNotSupported {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourceNotSupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedResourceRulesInvalid {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourceRulesInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedResourcesInvalid {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourcesInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedResourcesNotFound {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourcesNotFound userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedResourcesNotSealed {
  NSString *expected = @"Yes, but resources invalid";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSResourcesNotSealed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedReqFailed {
  NSString *expected = @"Yes, but failed requirement validation";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSReqFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedReqInvalid {
  NSString *expected = @"Yes, but failed requirement validation";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSReqInvalid userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedReqUnsupported {
  NSString *expected = @"Yes, but failed requirement validation";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSReqUnsupported userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedInfoPlistFailed {
  NSString *expected = @"Yes, but can't validate as Info.plist is missing";
  NSError *err = [NSError errorWithDomain:@"" code:errSecCSInfoPlistFailed userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

- (void)testCodeSignedDefault {
  NSString *expected = @"Yes, but failed to validate (999)";
  NSError *err = [NSError errorWithDomain:@"" code:999 userInfo:nil];
  OCMStub([self.cscMock initWithBinaryPath:OCMOCK_ANY
                                     error:[OCMArg setTo:err]]).andReturn(self.cscMock);
  XCTAssertEqualObjects(self.cfi.codeSigned(self.cfi), expected);
}

@end
