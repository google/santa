mod column_builder;
mod page_builder;
mod table;
mod value;

use parquet2::bloom_filter;
use table::{write_row_group, Options, Table};

#[cxx::bridge(namespace = "pedro::wire")]
mod ffi {
    extern "Rust" {
        type Table;
    }
}

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
    use super::{write_row_group, Options};
    use crate::{column_builder::ColumnBuilder, value::Value};
    use parquet2::{
        compression::{BrotliLevel, CompressionOptions},
        metadata::SchemaDescriptor,
        schema::types::{ParquetType, PhysicalType},
        write::{FileWriter, Version, WriteOptions},
    };
    use std::io::Cursor;

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

        let cursor: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut writer = FileWriter::new(cursor, schema.clone(), options.write_options, None);

        let mut columns = schema
            .columns()
            .iter()
            .map(|column| {
                ColumnBuilder::new(
                    options.page_size,
                    column.descriptor.clone(),
                    options.compression_options,
                )
            })
            .collect::<Vec<_>>();

        for i in 0..1000 {
            columns[0].push(Value::I32(i)).expect("push failed");
            columns[1]
                .push(Value::I64((i * 2).into()))
                .expect("push failed");

            let s = format!("integer_{}", i);
            columns[2]
                .push(Value::Bytes(s.as_bytes()))
                .expect("push failed");
        }
        write_row_group(&mut writer, &mut columns).unwrap();

        let result = writer.into_inner().into_inner();
        assert!(!result.is_empty());
        println!("{:?}", result);
    }
}
