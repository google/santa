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
