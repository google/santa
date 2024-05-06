#include <iostream>

#include "Source/santad/Logs/EndpointSecurity/ParquetLogger/gen/cpp_api.rs.h"

// This demonstrates the use of the C++ API for parquet_logger, which is
// implemented in Rust. The C++ API uses an opaque type called Table, which is
// returned as a Box (effectively a unique_ptr).
//
// To easily check that the file is valid, run the e2e_test in the same
// directory.
int main(int argc, char* argv[]) {
  try {
    if (argc < 2) {
      std::cout << "Usage: " << argv[0] << " <path>" << std::endl;
      return 1;
    }

    // IMPORTANT: If you change anything about the file, you MUST ALSO change
    // check_parquet_file.py, otherwise the e2e test will break.

    // Make me a table builder:
    auto args = pedro::wire::table_args_new("test_table", argv[1]);

    // Declare me some columns:
    pedro::wire::table_args_add_column(*args, "number",
                                       pedro::wire::CxxColumnType::Int32);
    pedro::wire::table_args_add_column(*args, "text",
                                       pedro::wire::CxxColumnType::ByteArray);
    pedro::wire::table_args_add_column(*args, "big_number",
                                       pedro::wire::CxxColumnType::Int64);
    auto table = pedro::wire::table_new(std::move(args));

    // Push one row:
    pedro::wire::table_push_i32(*table, 0, 1337);
    pedro::wire::table_push_string(*table, 1, "Hello, world!");
    pedro::wire::table_push_i64(*table, 2, 0xdeadbeef);

    // You can also push column by column - here three rows at a time.
    pedro::wire::table_push_i32(*table, 0, 1);
    pedro::wire::table_push_i32(*table, 0, 2);
    pedro::wire::table_push_i32(*table, 0, 3);

    pedro::wire::table_push_string(*table, 1, "Hello, world!");
    pedro::wire::table_push_string(*table, 1, "Hello, world!");
    pedro::wire::table_push_string(*table, 1, "Good bye, world!");

    pedro::wire::table_push_i64(*table, 2, 0xdeadbeef);
    pedro::wire::table_push_i64(*table, 2, 0xcafed00d);
    pedro::wire::table_push_i64(*table, 2, 0xfeedface);

    // As long as all columns are of equal lengths, we can now flush. (If
    // they're not, we'll get an exception.)
    pedro::wire::table_flush(*table);
    // Flush doesn't write the table footer - it only writes the data in the
    // buffer. To finalize the parquet file, we need to destroy the table.
    pedro::wire::table_end(std::move(table));

    std::cout << "Successfully wrote the example parquet file " << argv[0] << std::endl;
  } catch (std::exception& e) {
    std::cout << "Error writing parquet file:" << std::endl;
    std::cout << e.what() << std::endl;
  }
  return 0;
}
