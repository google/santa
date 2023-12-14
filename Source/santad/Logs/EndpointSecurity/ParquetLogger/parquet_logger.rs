//! This package provides an opinionated API for producing a Parquet file
//! containing a simple table. It's intended to be easy to use from both Rust
//! and C++ code, and uses Cxx to expose a C++ API. (See cpp_api.rs.)
//! 
//! We take the following simplifying assumptions:
//! 
//! * All fields are always required (no NULLs).
//! * All fields are simple types: integers, floats and strings.
//! * All files are brotli-compressed.
//! 
//! The API provides reasonable defaults for many of the knobs Parquet exposes,
//! and doesn't allow overriding most of them. This is intentional - the goal is
//! to be as simple to use as possible.
//! 
//! To get started from C++, look at cpp_api.rs. To get started from Rust, look
//! at the Table type in table.rs.
//! 
//! # Implementation Notes
//! 
//! The API is implemented on top of parquet2, a minimal reimplamentation of the
//! official arrow crate. We chose parquet2 for its simplicity, compilation
//! speed and lack of unsafe code. (The official arrow project is extremely
//! large and depends on Boost in C++.)
//! 
//! The code structure roughly mirrors that of a parquet file:
//! 
//! * Table: represents a parquet file, which consists of one or more row
//!   groups.
//! * ColumnBuilder: represents a column chunk in a row group.
//! * PageBuilder: represents a data page in a column chunk.
//! * Value: represents a single scalar (number or byte blob) in a data page.
//! 
//! Correctness, including of types, is enforced at runtime. Value, rather than
//! being a generic type, is an enumeration (discriminated union) that can hold
//! any of the supported types. This is done for two reasons:
//! 
//! 1. It makes the code eaiser to understand - multiple layers of generic
//!    traits are required for static type checking of column chunks and pages.
//! 2. The Table type must expose a runtime-generic way of setting a cell in a
//!    column, and this is the most common way of using the API, so any savings
//!    gained from static type checking would be bypassed by the most common
//!    code path anyway.
//! 
//! # Future Work
//! 
//! * Support fixed-length byte arrays.
//! * Reimplement FileWriter to use an arena-style buffer instead of nested
//!   iterators.
//! * More work on code size - the build size (in opt) is about 3.5 MiB, which
//!   could be reduced further by stripping unused compression code.

mod column_builder;
mod cpp_api;
mod page_builder;
mod table;
mod value;
mod writer;

use parquet2::bloom_filter;

// This is just some POC code for CXX that'll be removed later.
// DONOTSUBMIT: Remove this before finishing the PR.
#[no_mangle]
pub extern "C" fn parquet2_1337_bloom_filter_contains(x: i64) -> bool {
    let mut bits = vec![0; 32];
    bloom_filter::insert(&mut bits, bloom_filter::hash_native::<i64>(1337));
    bloom_filter::is_in_set(&bits, bloom_filter::hash_native(x))
}

#[cfg(test)]
mod test {
    use crate::{
        table::{Options, Table},
        value::Value,
        writer::Writer,
    };
    use parquet2::{
        compression::{BrotliLevel, CompressionOptions},
        metadata::SchemaDescriptor,
        schema::types::{ParquetType, PhysicalType},
        write::{Version, WriteOptions},
    };

    #[test]
    fn test_write() {
        let options = Options {
            write_options: WriteOptions {
                write_statistics: true,
                version: Version::V1,
            },
            compression_options: CompressionOptions::Brotli(Some(BrotliLevel::try_new(5).unwrap())),
            // compression_options: CompressionOptions::Uncompressed,
            page_size: 1024,
        };

        let schema = SchemaDescriptor::new(
            "schema".to_string(),
            vec![
                ParquetType::from_physical("a".to_string(), PhysicalType::Int32),
                ParquetType::from_physical("b".to_string(), PhysicalType::Int64),
                ParquetType::from_physical("c".to_string(), PhysicalType::ByteArray),
            ],
        );

        let writer = Writer::from_memory(schema.clone(), options.write_options, vec![]);
        let mut table = Table::new(schema, options, writer);

        for i in 0..1000 {
            table.push(0, Value::I32(i)).expect("push failed");
            table
                .push(1, Value::I64((i * 2).into()))
                .expect("push failed");

            let s = format!("integer_{}", i);
            table
                .push(2, Value::Bytes(s.as_bytes()))
                .expect("push failed");
        }
        table.flush().expect("flush failed");
        table.end().expect("end failed");

        let (_schema, writer, _options) = table.into_inner();
        let writer = if let Writer::Memory(w) = writer {
            w
        } else {
            panic!("Expected Writer::Memory");
        };
        let result = writer.into_inner();
        assert!(!result.is_empty());
        println!("{:?}", result);
    }
}
