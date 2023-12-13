mod column_builder;
mod page_builder;
mod value;

use column_builder::{ColumnBuilder, ColumnChunk};
use page_builder::{ByteArrayPageBuilder, NativePageBuilder, PageBuilder};
use parquet2::{
    bloom_filter,
    compression::CompressionOptions,
    encoding::Encoding,
    error::{Error, Result},
    metadata::{Descriptor, SchemaDescriptor},
    page::{CompressedPage, DataPage, DataPageHeader, DataPageHeaderV1, Page},
    statistics::{serialize_statistics, PrimitiveStatistics},
    types::NativeType,
    write::{Compressor, DynIter, DynStreamingIterator, FileWriter, WriteOptions},
};
use std::{cmp::PartialOrd, io::Write};
use value::Value;

#[cxx::bridge(namespace = "pedro::wire")]
mod ffi {
    extern "Rust" {}
}

// This is just some POC code for CXX that'll be removed later.
// DONOTSUBMIT: Remove this before finishing the PR.
#[no_mangle]
pub extern "C" fn parquet2_1337_bloom_filter_contains(x: i64) -> bool {
    let mut bits = vec![0; 32];
    bloom_filter::insert(&mut bits, bloom_filter::hash_native::<i64>(1337));
    bloom_filter::is_in_set(&bits, bloom_filter::hash_native(x))
}

fn write_row_group<W: Write>(
    writer: &mut FileWriter<W>,
    mut columns: Vec<Box<dyn ColumnChunk>>,
    _compression_options: CompressionOptions,
) -> Result<()> {
    let row_group = columns.iter_mut().map(|column| Ok(column.drain()));
    let row_group = DynIter::new(row_group);
    writer.write(row_group)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Options {
    pub write_options: WriteOptions,
    pub compression_options: CompressionOptions,
    pub page_size: usize,
}

#[cfg(test)]
mod test {
    use super::{write_row_group, Options};
    use crate::{ByteArrayPageBuilder, ColumnChunk, PageBuilder};
    use parquet2::{
        compression::CompressionOptions,
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
            // compression_options: CompressionOptions::Brotli(Some(BrotliLevel::try_new(5).unwrap())),
            compression_options: CompressionOptions::Uncompressed,
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

        let mut builder_a = super::ColumnBuilder::<i32, super::NativePageBuilder<i32>>::new(
            options.page_size,
            schema.columns()[0].descriptor.clone(),
            options.compression_options,
        );

        let mut builder_b = super::ColumnBuilder::<i64, super::NativePageBuilder<i64>>::new(
            options.page_size,
            schema.columns()[1].descriptor.clone(),
            options.compression_options,
        );

        let mut builder_c = super::ColumnBuilder::<&[u8], ByteArrayPageBuilder>::new(
            options.page_size,
            schema.columns()[2].descriptor.clone(),
            options.compression_options,
        );

        for i in 0..1000 {
            builder_a.push(i);
            builder_b.push((i * 2).into());

            let s = format!("integer_{}", i);
            // Can't do builder_c.push(s.as_bytes()), because rust wrongly
            // infers that the lifetime of s.as_bytes() needs to be the same as
            // builder_c. However, borrowing the page_builder first lets the
            // checker follow along.
            let p = builder_c.page_builder(s.len()).push(s.as_bytes());
        }

        let mut columns: Vec<Box<dyn ColumnChunk>> = vec![];
        let column_a: Box<dyn ColumnChunk> = Box::new(builder_a);
        let column_b: Box<dyn ColumnChunk> = Box::new(builder_b);
        let column_c: Box<dyn ColumnChunk> = Box::new(builder_c);
        columns.push(column_a);
        columns.push(column_b);
        columns.push(column_c);

        write_row_group(&mut writer, columns, options.compression_options).unwrap();

        let result = writer.into_inner().into_inner();
        assert!(!result.is_empty());
        println!("{:?}", result);
    }
}
