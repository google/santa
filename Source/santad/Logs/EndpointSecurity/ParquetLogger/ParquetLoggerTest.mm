#import <XCTest/XCTest.h>
#import <filesystem>
#import "ParquetLogger.h"

@interface ParquetLoggerTest : XCTestCase
@end

@implementation ParquetLoggerTest

- (void)testWriteTable {
  auto tmp_path = std::filesystem::temp_directory_path();
  try {
    auto args =
      pedro::wire::table_args_new("test_table", (tmp_path / "test_table.parquet").string());

    pedro::wire::table_args_add_column(*args, "number", pedro::wire::CxxColumnType::Int32);
    pedro::wire::table_args_add_column(*args, "text", pedro::wire::CxxColumnType::ByteArray);
    auto table = pedro::wire::table_new(std::move(args));

    pedro::wire::table_push_i32(*table, 0, 1337);
    pedro::wire::table_push_string(*table, 1, "foo");

    pedro::wire::table_push_i32(*table, 0, 1);
    pedro::wire::table_push_i32(*table, 0, 2);
    pedro::wire::table_push_i32(*table, 0, 3);

    pedro::wire::table_push_string(*table, 1, "bar");
    pedro::wire::table_push_string(*table, 1, "baz");
    pedro::wire::table_push_string(*table, 1, "qux");

    pedro::wire::table_flush(*table);
    pedro::wire::table_end(std::move(table));
  } catch (const std::exception &e) {
    // None of this should throw.
    XCTAssertFalse(true, "Exception: %s", e.what());
  }

  // The file should exist as expected.
  std::filesystem::path testFilePath = tmp_path / "test_table.parquet";
  XCTAssertTrue(std::filesystem::exists(testFilePath));
}

- (void)testInvalidFlushThrows {
  auto tmp_path = std::filesystem::temp_directory_path();
  auto args = pedro::wire::table_args_new("test_table", (tmp_path / "test_table.parquet").string());
  pedro::wire::table_args_add_column(*args, "number", pedro::wire::CxxColumnType::Int32);
  pedro::wire::table_args_add_column(*args, "text", pedro::wire::CxxColumnType::ByteArray);

  auto table = pedro::wire::table_new(std::move(args));
  pedro::wire::table_push_i32(*table, 0, 1);
  pedro::wire::table_push_i32(*table, 0, 2);

  // This should throw because we haven't pushed data to all columns.
  XCTAssertThrows(pedro::wire::table_flush(*table));
}

@end
