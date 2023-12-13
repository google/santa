use super::Value;
use parquet2::{
    encoding::Encoding,
    metadata::Descriptor,
    page::{DataPage, DataPageHeader, DataPageHeaderV1, Page},
    statistics::{serialize_statistics, PrimitiveStatistics},
    types::NativeType,
};
use std::cmp::PartialOrd;

// A page builder serializes primitive values into bytes and appends them to a
// page (buffer). Implementations are provided for NativeType and &[u8] (byte
// array).
pub trait PageBuilder<T: Value>: Send + Sync {
    fn new(buffer: Vec<u8>, descriptor: Descriptor) -> Self;
    // Serialize and append a value to the page.
    fn push(&mut self, value: T);
    // The size of the page in bytes.
    fn size(&self) -> usize;
    // Finalize and return the page.
    fn into_page(self) -> Page;
}

// Builds a page of variable length by arrays. Used for strings and other blobs.
pub struct ByteArrayPageBuilder {
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
pub struct NativePageBuilder<T: NativeType + PartialOrd> {
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
