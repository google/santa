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

#import "SNTDERDecoder.h"

@interface SNTDERDecoder (Testing)
+ (NSString *)decodeOIDWithBytes:(unsigned char *)bytes length:(NSUInteger)length;
@end

@interface SNTDERDecoderTest : XCTestCase
@end

@implementation SNTDERDecoderTest

- (void)setUp {
  [super setUp];
}

- (void)tearDown {
  [super tearDown];
}

- (void)testOIDDecoding {
  unsigned char oidBytes1[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14};
  NSString *oidStr = [SNTDERDecoder decodeOIDWithBytes:oidBytes1 length:sizeof(oidBytes1)];
  XCTAssertEqualObjects(oidStr, @"1.3.6.1.4.1.311.21.20");

  unsigned char oidBytes2[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0xAB, 0x0E, 0x01, 0x05, 0x2F };
  oidStr = [SNTDERDecoder decodeOIDWithBytes:oidBytes2 length:sizeof(oidBytes2)];
  XCTAssertEqualObjects(oidStr, @"1.3.6.1.4.1.5518.1.5.47");

  unsigned char oidBytes3[] = {0x56, 0x04, 0x0A};
  oidStr = [SNTDERDecoder decodeOIDWithBytes:oidBytes3 length:sizeof(oidBytes3)];
  XCTAssertEqualObjects(oidStr, @"2.6.4.10");	
}

@end
