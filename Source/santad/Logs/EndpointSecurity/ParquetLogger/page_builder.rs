use crate::value::Value;

use parquet2::{
    encoding::Encoding,
    error::{Error, Result},
    metadata::Descriptor,
    page::{DataPage, DataPageHeader, DataPageHeaderV1, Page},
    schema::types::PhysicalType,
    statistics::{serialize_statistics, BinaryStatistics, PrimitiveStatistics},
    types::NativeType,
};
use std::cmp::PartialOrd;

/// A page builder serializes primitive values into bytes and appends them to a
/// page (buffer). Implementations are provided for NativeType and &[u8] (byte
/// array).
pub struct PageBuilder {
    page_builder: InnerBuilder,
}

impl PageBuilder {
    pub fn new(descriptor: Descriptor, buffer: Vec<u8>) -> Result<Self> {
        match descriptor.primitive_type.physical_type {
            PhysicalType::ByteArray => Ok(Self {
                page_builder: InnerBuilder::ByteArray(ByteArrayPage::new(buffer, descriptor)),
            }),
            PhysicalType::Int32 => Ok(Self {
                page_builder: InnerBuilder::I32(NativePage::new(buffer, descriptor)),
            }),
            PhysicalType::Int64 => Ok(Self {
                page_builder: InnerBuilder::I64(NativePage::new(buffer, descriptor)),
            }),
            PhysicalType::Float => Ok(Self {
                page_builder: InnerBuilder::F32(NativePage::new(buffer, descriptor)),
            }),
            PhysicalType::Double => Ok(Self {
                page_builder: InnerBuilder::F64(NativePage::new(buffer, descriptor)),
            }),
            _ => Err(Error::FeatureNotSupported(format!(
                "Unsupported type: {:?}",
                descriptor.primitive_type
            ))),
        }
    }

    pub fn push(&mut self, value: Value) -> Result<()> {
        match self.page_builder {
            InnerBuilder::ByteArray(ref mut builder) => builder.push(value.as_bytes()?),
            InnerBuilder::I32(ref mut builder) => builder.push(value.as_i32()?),
            InnerBuilder::I64(ref mut builder) => builder.push(value.as_i64()?),
            InnerBuilder::F32(ref mut builder) => builder.push(value.as_f32()?),
            InnerBuilder::F64(ref mut builder) => builder.push(value.as_f64()?),
        }
        Ok(())
    }

    pub fn size(&self) -> usize {
        match self.page_builder {
            InnerBuilder::ByteArray(ref builder) => builder.size(),
            InnerBuilder::I32(ref builder) => builder.size(),
            InnerBuilder::I64(ref builder) => builder.size(),
            InnerBuilder::F32(ref builder) => builder.size(),
            InnerBuilder::F64(ref builder) => builder.size(),
        }
    }

    pub fn count(&self) -> usize {
        match self.page_builder {
            InnerBuilder::ByteArray(ref builder) => builder.count,
            InnerBuilder::I32(ref builder) => builder.count,
            InnerBuilder::I64(ref builder) => builder.count,
            InnerBuilder::F32(ref builder) => builder.count,
            InnerBuilder::F64(ref builder) => builder.count,
        }
    }

    pub fn into_page(self) -> Page {
        match self.page_builder {
            InnerBuilder::ByteArray(builder) => builder.into_page(),
            InnerBuilder::I32(builder) => builder.into_page(),
            InnerBuilder::I64(builder) => builder.into_page(),
            InnerBuilder::F32(builder) => builder.into_page(),
            InnerBuilder::F64(builder) => builder.into_page(),
        }
    }
}

enum InnerBuilder {
    ByteArray(ByteArrayPage),
    I32(NativePage<i32>),
    I64(NativePage<i64>),
    F32(NativePage<f32>),
    F64(NativePage<f64>),
}

/// Builds a page of variable length by arrays. Used for strings and other
/// blobs.
pub struct ByteArrayPage {
    buffer: Vec<u8>,
    count: usize,
    descriptor: Descriptor,
}

impl ByteArrayPage {
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
        let statistics = BinaryStatistics {
            primitive_type: self.descriptor.primitive_type.clone(),
            null_count: Some(0),  // No NULLs allowed.
            distinct_count: None, // Not worth the cost of counting.
            max_value: None,
            min_value: None,
        };

        let header = DataPageHeaderV1 {
            num_values: self.count as i32,
            encoding: Encoding::Plain.into(),
            definition_level_encoding: Encoding::Rle.into(),
            repetition_level_encoding: Encoding::Rle.into(),
            statistics: Some(serialize_statistics(&statistics)),
        };

        Page::Data(DataPage::new(
            DataPageHeader::V1(header),
            self.buffer,
            self.descriptor,
            Some(self.count),
        ))
    }
}

/// A page of numbers using plain encoding. This is implemented (and fast) for
/// most native numeric types. (Int96 isn't used at the moment.)
pub struct NativePage<T: NativeType + PartialOrd> {
    buffer: Vec<u8>,
    count: usize,
    statistics: PrimitiveStatistics<T>,
    descriptor: Descriptor,
}

impl<T: NativeType + PartialOrd> NativePage<T> {
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
