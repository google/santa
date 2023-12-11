#import <XCTest/XCTest.h>
#import "ParquetLogger.h"

@interface ParquetLoggerTest : XCTestCase
@end

@implementation ParquetLoggerTest

// Currently, this just demonstrates that Rust code can be called into.
- (void)testBasic {
  XCTAssertFalse(FilterContains(1338));
  XCTAssertTrue(FilterContains(1337));
}

@end
