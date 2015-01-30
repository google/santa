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

#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"

/**
 Tests for @c SNTCodesignChecker

 Most of these tests rely on some facts about @c launchd:

 * launchd is in /sbin
 * launchd is PID 1
 * launchd is signed
 * launchd's leaf cert has a CN of "Software Signing"
 * launchd's leaf cert has an OU of "Apple Software"
 * launchd's leaf cert has an ON of "Apple Inc."

 These facts are pretty stable, so shouldn't be a problem.
**/
@interface SNTCodesignCheckerTest : XCTestCase
@end

@implementation SNTCodesignCheckerTest

- (void)testInitWithBinaryPath {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  XCTAssertNotNil(sut);
}

- (void)testInitWithInvalidBinaryPath {
  SNTCodesignChecker *sut =
      [[SNTCodesignChecker alloc] initWithBinaryPath:@"/tmp/this/file/doesnt/exist"];
  XCTAssertNil(sut);
}

- (void)testInitWithPID {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut);
}

- (void)testInitWithInvalidPID {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithPID:999999999];
  XCTAssertNil(sut);
}

- (void)testInitWithSelf {
  // n.b: 'self' in this case is xctest, which should always be signed.
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithSelf];
  XCTAssertNotNil(sut);
}

- (void)testPlainInit {
  XCTAssertThrows([[SNTCodesignChecker alloc] init]);
}

- (void)testDescription {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithPID:1];
  XCTAssertEqualObjects([sut description],
                        @"In-memory binary, signed by Apple Inc., located at: /sbin/launchd");
}

- (void)testLeafCertificate {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut.leafCertificate);
}

- (void)testBinaryPath {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithPID:1];
  XCTAssertEqualObjects(sut.binaryPath, @"/sbin/launchd");
}

- (void)testSigningInformationMatches {
  SNTCodesignChecker *sut1 = [[SNTCodesignChecker alloc] initWithBinaryPath:@"/sbin/launchd"];
  SNTCodesignChecker *sut2 = [[SNTCodesignChecker alloc] initWithPID:1];
  XCTAssertTrue([sut1 signingInformationMatches:sut2]);
}

- (void)testCodeRef {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithSelf];
  XCTAssertNotNil((id)sut.codeRef);
}

- (void)testSigningInformation {
  SNTCodesignChecker *sut = [[SNTCodesignChecker alloc] initWithPID:1];
  XCTAssertNotNil(sut.signingInformation);
  XCTAssertEqualObjects(sut.signingInformation[@"source"], @"embedded");
}

@end
