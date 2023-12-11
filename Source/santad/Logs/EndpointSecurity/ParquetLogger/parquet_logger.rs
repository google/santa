use parquet2::{
    bloom_filter,
    compression::CompressionOptions,
    encoding::Encoding,
    error::{Error, Result},
    metadata::{ Descriptor, SchemaDescriptor},
    page::{CompressedPage, DataPage, DataPageHeader, DataPageHeaderV1, Page},
    statistics::{serialize_statistics, PrimitiveStatistics},
    types::NativeType,
    write::{Compressor, DynIter, DynStreamingIterator, FileWriter, WriteOptions},
};
use std::{cmp::PartialOrd, io::Write};

#[cxx::bridge(namespace = "pedro::wire")]
mod ffi {
    extern "Rust" {
    }
}

// A value can be written to a page in a column chunk in a row group in a
// parquet file in the house that Jack built.
//
// Not much is required of a value - it must have a known size and be
// async-save. The list of supported value types matches NativeType + string.
trait Value: PartialOrd + Send + Sync {
    // The size of this type is efficiently known.
    // This typically means fixed width or string.
    fn dyn_size(&self) -> usize;
}

impl Value for String {
    fn dyn_size(&self) -> usize {
        self.len()
    }
}

impl Value for &[u8] {
    fn dyn_size(&self) -> usize {
        self.len()
    }
}

trait Number: Sized + PartialOrd + Send + Sync {}

// These are the only numeric types supported by parquet. (There is also int96,
// but we don't worry about that.)
impl Number for i32 {}
impl Number for i64 {}
impl Number for f32 {}
impl Number for f64 {}

// NativeTypes are all values.
impl<T: Number> Value for T {
    fn dyn_size(&self) -> usize {
        std::mem::size_of::<T>()
    }
}

// A column chunk is a collection of pages. It can be drained to get compressed
// pages out. After the compressed pages are written to a file, the column chunk
// can be reused.
trait ColumnChunk: Send + Sync {
    fn drain<'a>(&'a mut self) -> DynStreamingIterator<'a, CompressedPage, Error>;
    // fn push(&mut self, value: Box<dyn Value>);
    // fn page_builder<T: Value, P:PageBuilder<T>>(&mut self, size_hint: usize) -> &mut P;

    // fn page_builder_i32(&mut self, size_hint: usize) -> &mut NativePageBuilder<i32>;
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

// Builds a column chunk from primitive values.
struct ColumnBuilder<T: Value, P: PageBuilder<T>> {
    pages: Vec<P>,
    page_size: usize,
    descriptor: Descriptor,
    compression_options: CompressionOptions,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Value, P: PageBuilder<T>> ColumnBuilder<T, P> {
    fn new(
        page_size: usize,
        descriptor: Descriptor,
        compression_options: CompressionOptions,
    ) -> Self {
        Self {
            pages: vec![],
            page_size: page_size,
            descriptor: descriptor,
            compression_options,
            _phantom: std::marker::PhantomData,
        }
    }

    fn push(&mut self, value: T) {
        self.page_builder(value.dyn_size()).push(value);
    }

    fn page_builder(&mut self, size_hint: usize) -> &mut P {
        let last_page = match self.pages.last_mut() {
            Some(page) => page,
            None => {
                let mut buffer = vec![];
                buffer.reserve(self.page_size);
                self.pages.push(P::new(buffer, self.descriptor.clone()));
                self.pages.last_mut().unwrap()
            }
        };

        if last_page.size() + size_hint > self.page_size {
            let mut buffer = vec![];
            buffer.reserve(self.page_size);
            self.pages.push(P::new(buffer, self.descriptor.clone()));
        }

        self.pages.last_mut().unwrap()
    }
}

impl<T: Value, P: PageBuilder<T>> ColumnChunk for ColumnBuilder<T, P> {
    fn drain<'a>(&'a mut self) -> DynStreamingIterator<'a, CompressedPage, Error> {
        let pages: Vec<Result<Page>> = self
            .pages
            .drain(..)
            .map(|page| Ok(page.into_page()))
            .collect();
        let compressor = Compressor::new(
            DynIter::new(pages.into_iter()),
            self.compression_options,
            vec![],
        );
        DynStreamingIterator::new(compressor)
    }
}

// A page builder serializes primitive values into bytes and appends them to a
// page (buffer). Implementations are provided for NativeType and &[u8] (byte
// array).
trait PageBuilder<T: Value>: Send + Sync {
    fn new(buffer: Vec<u8>, descriptor: Descriptor) -> Self;
    // Serialize and append a value to the page.
    fn push(&mut self, value: T);
    // The size of the page in bytes.
    fn size(&self) -> usize;
    // Finalize and return the page.
    fn into_page(self) -> Page;
}

// Builds a page of variable length by arrays. Used for strings and other blobs.
struct ByteArrayPageBuilder {
    buffer: Vec<u8>,
    count: usize,
    descriptor: Descriptor,
}

impl PageBuilder<&[u8]> for ByteArrayPageBuilder {
    fn new(mut buffer: Vec<u8>, descriptor: Descriptor) -> Self {
        buffer.clear();
        Self {
            buffer: buffer,
            count: 0,
            descriptor: descriptor,
        }
    }

    fn push(&mut self, value: &[u8]) {
        self.buffer
            .extend_from_slice((value.len() as i32).to_le_bytes().as_ref());
        self.buffer.extend_from_slice(value);
        self.count += 1;
    }

    fn size(&self) -> usize {
        self.buffer.len()
    }

    fn into_page(self) -> Page {
        let header = DataPageHeaderV1 {
            num_values: self.count as i32,
            encoding: Encoding::Plain.into(),
            definition_level_encoding: Encoding::Rle.into(),
            repetition_level_encoding: Encoding::Rle.into(),
            statistics: None,
        };

        Page::Data(DataPage::new(
            DataPageHeader::V1(header),
            self.buffer,
            self.descriptor,
            Some(self.count),
        ))
    }
}

// A page of numbers using plain encoding. This is implemented (and fast) for
// most native numeric types. (Int96 isn't used at the moment.)
struct NativePageBuilder<T: NativeType + PartialOrd> {
    buffer: Vec<u8>,
    count: usize,
    statistics: PrimitiveStatistics<T>,
    descriptor: Descriptor,
}

impl<T: NativeType + Value + PartialOrd> PageBuilder<T> for NativePageBuilder<T> {
    fn new(mut buffer: Vec<u8>, descriptor: Descriptor) -> Self {
        buffer.clear();
        Self {
            buffer: buffer,
            count: 0,
            statistics: PrimitiveStatistics {
                primitive_type: descriptor.primitive_type.clone(),
                null_count: Some(0),  // No NULLs allowed.
                distinct_count: None, // Not worth the cost of counting.
                max_value: None,
                min_value: None,
            },
            descriptor: descriptor,
        }
    }

    fn push(&mut self, value: T) {
        self.buffer.extend_from_slice(value.to_le_bytes().as_ref());
        self.count += 1;
        // TODO(adam): Keep track of min and max and maybe distinct.
    }

    fn size(&self) -> usize {
        self.buffer.len()
    }

    fn into_page(self) -> Page {
        let header = DataPageHeaderV1 {
            num_values: self.count as i32,
            encoding: Encoding::Plain.into(),
            definition_level_encoding: Encoding::Rle.into(),
            repetition_level_encoding: Encoding::Rle.into(),
            statistics: Some(serialize_statistics(&self.statistics)),
        };

        Page::Data(DataPage::new(
            DataPageHeader::V1(header),
            self.buffer,
            self.descriptor,
            Some(self.count),
        ))
    }
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

// This is just some POC code for CXX that'll be removed later.
// DONOTSUBMIT: Remove this before finishing the PR.
#[no_mangle]
pub extern "C" fn parquet2_1337_bloom_filter_contains(x: i64) -> bool {
    let mut bits = vec![0; 32];
    bloom_filter::insert(&mut bits, bloom_filter::hash_native::<i64>(1337));
    bloom_filter::is_in_set(&bits, bloom_filter::hash_native(x))
}
