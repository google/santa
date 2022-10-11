/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/santad/Logs/EndpointSecurity/Serializers/SanitizableString.h"

#include <EndpointSecurity/ESTypes.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <sstream>
#include <string_view>

#include "Source/common/TestUtils.h"

using santa::santad::logs::endpoint_security::serializers::SanitizableString;

@interface SanitizableStringTest : XCTestCase
@end

@implementation SanitizableStringTest

- (void)testSanitizeString {
  const char *empty = "";
  size_t emptyLen = strlen(empty);
  const char *noSanitize = "nothing_to_sanitize";
  size_t noSanitizeLen = strlen(noSanitize);
  const char *sanitizable = "sani|tizable";
  size_t sanitizableLen = strlen(sanitizable);

  // NULL pointers are handled
  XCTAssertFalse(SanitizableString::SanitizeString(NULL).has_value());

  // Non-sanitized strings return std::nullopt
  XCTAssertEqual(std::nullopt, SanitizableString::SanitizeString(empty));
  XCTAssertEqual(std::nullopt, SanitizableString::SanitizeString(noSanitize));

  // Intentional pointer compare to ensure the data member of the returned
  // string_view matches the original buffer when not sanitized, and not equal
  // when the string needs sanitization
  XCTAssertEqual(empty, SanitizableString(empty, emptyLen).Sanitized().data());
  XCTAssertEqual(noSanitize, SanitizableString(noSanitize, noSanitizeLen).Sanitized().data());
  XCTAssertNotEqual(sanitizable, SanitizableString(sanitizable, sanitizableLen).Sanitized().data());

  // Ensure the `String` method always returns the unsanitized buffer
  XCTAssertEqual(empty, SanitizableString(empty, emptyLen).String().data());
  XCTAssertEqual(noSanitize, SanitizableString(noSanitize, noSanitizeLen).String().data());
  XCTAssertEqual(sanitizable, SanitizableString(sanitizable, sanitizableLen).String().data());

  XCTAssertCStringEqual(SanitizableString(@"|").Sanitized().data(), "<pipe>");
  XCTAssertCStringEqual(SanitizableString(@"\n").Sanitized().data(), "\\n");
  XCTAssertCStringEqual(SanitizableString(@"\r").Sanitized().data(), "\\r");

  XCTAssertCStringEqual(SanitizableString(@"a\nb\rc|").Sanitized().data(), "a\\nb\\rc<pipe>");
  XCTAssertCStringEqual(SanitizableString(@"a|trail").Sanitized().data(), "a<pipe>trail");

  // Handle some long strings
  NSString *base = [NSString stringWithFormat:@"%@|abc", [@"" stringByPaddingToLength:66 * 1024
                                                                           withString:@"A"
                                                                      startingAtIndex:0]];

  NSString *want = [NSString stringWithFormat:@"%@<pipe>abc", [@"" stringByPaddingToLength:66 * 1024
                                                                                withString:@"A"
                                                                           startingAtIndex:0]];

  XCTAssertCStringEqual(SanitizableString(base).Sanitized().data(), [want UTF8String]);
}

- (void)testStream {
  // Test that using the `<<` operator will sanitize the string
  std::ostringstream ss;
  const char *sanitizable = "sani|tizable";
  const char *sanitized = "sani<pipe>tizable";
  es_string_token_t tok = {.length = strlen(sanitizable), .data = sanitizable};

  ss << SanitizableString(tok);

  XCTAssertCStringEqual(ss.str().c_str(), sanitized);
}

@end
