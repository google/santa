#import <XCTest/XCTest.h>
#import "Source/common/SNTConfiguratorHelperFunctions.h"

@interface SNTConfiguratorHelperFunctionsTests : XCTestCase
@end

@implementation SNTConfiguratorHelperFunctionsTests
- (void)testSplitListOfKeyValuePairsSplitByEquals {
  NSArray<NSDictionary *> *tests = @[
    @{
      @"description" : @"ensure an empty string produces an empty dict",
      @"input" : @"",
      @"expected" : @{}
    },
    @{
      @"description" : @"ensure welformed single pair works",
      @"input" : @"a=b",
      @"expected" : @{@"a" : @"b"}
    },
    @{
      @"description" : @"ensure welformed single pair works (w/whitespace)",
      @"input" : @"a = b",
      @"expected" : @{@"a" : @"b"}
    },
    @{
      @"description" : @"ensure welformed multiple pairs works",
      @"input" : @"a=b,c=d",
      @"expected" : @{@"a" : @"b", @"c" : @"d"}
    },
    @{
      @"description" : @"ensure welformed multiple pairs works",
      @"input" : @" a = b , c = d ",
      @"expected" : @{@"a" : @"b", @"c" : @"d"}
    }
  ];

  for (NSDictionary *test in tests) {
    XCTAssertEqualObjects(test[@"expected"], splitListOfKeyValuePairsSplitByEquals(test[@"input"]),
                          @"Failed %@", test[@"description"]);
  }
}
@end
