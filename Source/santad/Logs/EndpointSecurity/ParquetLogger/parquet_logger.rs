use parquet2::{
    bloom_filter,
    compression::CompressionOptions,
    encoding::Encoding,
    error::{Error, Result},
    metadata::{ColumnDescriptor, Descriptor},
    page::{CompressedPage, DataPage, DataPageHeader, DataPageHeaderV1, Page},
    statistics::{serialize_statistics, PrimitiveStatistics, Statistics},
    types::NativeType,
    write::{Compressor, DynIter, DynStreamingIterator, FileWriter, WriteOptions},
};
use std::{cmp::PartialOrd, io::Write};

// The size of this type is efficiently known.
// This typically means fixed width or string.
trait DynSized {
    fn dyn_size(&self) -> usize;
}

// NativeTypes as defined by parquet are all fixed width.
impl<T> DynSized for T
where
    T: Sized + NativeType,
{
    fn dyn_size(&self) -> usize {
        std::mem::size_of::<T>()
    }
}

// Strings have an efficient length. This is the only dynamically sized type in
// Parquet (technically called a byte array).
impl DynSized for str {
    fn dyn_size(&self) -> usize {
        self.len()
    }
}

// A value can be written to a page in a column chunk in a row group in a
// parquet file in the house that Jack built.
trait Value: DynSized + PartialOrd + Send + Sync {}

// NativeTypes are all values.
impl<T> Value for T where T: NativeType + PartialOrd {}

// Strings are also values.
impl Value for str {}

// A column chunk is a collection of pages. It can be drained to get compressed
// pages out. After the compressed pages are written to a file, the column chunk
// can be reused.
trait ColumnChunk: Send + Sync {
    fn drain<'a>(&'a mut self) -> DynStreamingIterator<'a, CompressedPage, Error>;
}

fn write<W: Write>(
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
        let last_page = match self.pages.last_mut() {
            Some(page) => page,
            None => {
                let mut buffer = vec![];
                buffer.reserve(self.page_size);
                self.pages.push(P::new(buffer, self.descriptor.clone()));
                self.pages.last_mut().unwrap()
            }
        };

        if last_page.size() + value.dyn_size() > self.page_size {
            let mut buffer = vec![];
            buffer.reserve(self.page_size);
            self.pages.push(P::new(buffer, self.descriptor.clone()));
        }
        self.pages.last_mut().unwrap().push(value);
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
// page (buffer). Implementations exist for NativeType and str.
trait PageBuilder<T: Value>: Send + Sync {
    fn new(buffer: Vec<u8>, descriptor: Descriptor) -> Self;
    fn push(&mut self, value: T);
    fn size(&self) -> usize;
    fn into_page(self) -> Page;
}

// TODO(adam): Serialize strings.
struct StringPageBuilder {
    buffer: Vec<u8>,
    count: usize,
    descriptor: Descriptor,
}

// A page of numbers using plain encoding. This is implemented (and fast) for
// most native numeric types. (Int96 could be added, but it seems pointless.)
struct NativePageBuilder<T: NativeType + PartialOrd> {
    buffer: Vec<u8>,
    count: usize,
    statistics: PrimitiveStatistics<T>,
    descriptor: Descriptor,
}

impl<T: NativeType + PartialOrd> PageBuilder<T> for NativePageBuilder<T> {
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

pub fn array_to_page_v1<T: NativeType>(
    array: &[T],
    options: &WriteOptions,
    descriptor: &Descriptor,
) -> Result<Page> {
    if array.is_empty() {
        return Err(Error::InvalidParameter("no empty arrays".to_string()));
    }
    let mut buffer = vec![];
    buffer.reserve(std::mem::size_of_val(&[array[0]]));
    let _iter = array.iter().map(|value| {
        buffer.extend_from_slice(value.to_le_bytes().as_ref());
    });

    let statistics = if options.write_statistics {
        let statistics = &PrimitiveStatistics {
            primitive_type: descriptor.primitive_type.clone(),
            null_count: Some(0), // All fields are required.
            distinct_count: None,
            max_value: array.iter().max_by(|x, y| x.ord(y)).copied(),
            min_value: array.iter().min_by(|x, y| x.ord(y)).copied(),
        } as &dyn Statistics;
        Some(serialize_statistics(statistics))
    } else {
        None
    };

    let header = DataPageHeaderV1 {
        num_values: array.len() as i32,
        encoding: Encoding::Plain.into(),
        definition_level_encoding: Encoding::Rle.into(),
        repetition_level_encoding: Encoding::Rle.into(),
        statistics,
    };

    Ok(Page::Data(DataPage::new(
        DataPageHeader::V1(header),
        buffer,
        descriptor.clone(),
        Some(array.len()),
    )))
}

fn column_to_pages<'a, T: NativeType>(
    options: &'a Options,
    column: &'a ColumnDescriptor,
    data: &'a [T],
) -> Result<DynStreamingIterator<'a, CompressedPage, parquet2::error::Error>> {
    let per_page = options.page_size / std::mem::size_of::<T>();
    let pages = data.chunks(per_page);
    let pages =
        pages.map(|page| array_to_page_v1::<T>(page, &options.write_options, &column.descriptor));
    // TODO(adam): Reuse the buffer between calls. (It requires care,
    // because this function is called from an iterator.)
    let pages = DynStreamingIterator::new(Compressor::new(
        DynIter::new(pages.into_iter()),
        options.compression_options,
        vec![],
    ));

    Ok(pages)
}


#[cfg(test)]
mod test {
    use crate::ColumnChunk;
    use parquet2::compression::CompressionOptions;
    use parquet2::metadata::SchemaDescriptor;
    use parquet2::schema::types::{ParquetType, PhysicalType};
    use parquet2::write::WriteOptions;
    use parquet2::write::{FileWriter, Version};
    use std::io::Cursor;
    use super::{write, Options};

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
            ],
        );

        let cursor: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let mut writer = FileWriter::new(cursor, schema.clone(), options.write_options, None);

        let mut builder_a: super::ColumnBuilder<i32, super::NativePageBuilder<i32>> =
            super::ColumnBuilder::<i32, super::NativePageBuilder<i32>>::new(
                options.page_size,
                schema.columns()[0].descriptor.clone(),
                options.compression_options,
            );

        let mut builder_b: super::ColumnBuilder<i64, super::NativePageBuilder<i64>> =
            super::ColumnBuilder::<i64, super::NativePageBuilder<i64>>::new(
                options.page_size,
                schema.columns()[1].descriptor.clone(),
                options.compression_options,
            );

        for i in 0..1000 {
            builder_a.push(i);
            builder_b.push((i * 2).into());
        }

        let mut columns: Vec<Box<dyn ColumnChunk>> = vec![];
        let column_a: Box<dyn ColumnChunk> = Box::new(builder_a);
        let column_b: Box<dyn ColumnChunk> = Box::new(builder_b);
        columns.push(column_a);
        columns.push(column_b);

        write(&mut writer, columns, options.compression_options).unwrap();

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

#[cxx::bridge(namespace = "pedro::wire")]
mod ffi {
    extern "Rust" {
        type EventHeader;
        fn log_event(hdr: &EventHeader);
    }
}

struct EventHeader {
    unix_timestamp: i64,
}

fn log_event(_hdr: &EventHeader) {}
