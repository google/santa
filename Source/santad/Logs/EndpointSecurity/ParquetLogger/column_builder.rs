use super::{PageBuilder, Value};
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

// A column chunk is a collection of pages. It can be drained to get compressed
// pages out. After the compressed pages are written to a file, the column chunk
// can be reused.
pub trait ColumnChunk: Send + Sync {
    fn drain<'a>(&'a mut self) -> DynStreamingIterator<'a, CompressedPage, Error>;
    // fn push(&mut self, value: Box<dyn Value>);
    // fn page_builder<T: Value, P:PageBuilder<T>>(&mut self, size_hint: usize) -> &mut P;

    // fn page_builder_i32(&mut self, size_hint: usize) -> &mut NativePageBuilder<i32>;
}

// Builds a column chunk from primitive values.
pub struct ColumnBuilder<T: Value, P: PageBuilder<T>> {
    pages: Vec<P>,
    page_size: usize,
    descriptor: Descriptor,
    compression_options: CompressionOptions,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Value, P: PageBuilder<T>> ColumnBuilder<T, P> {
    pub fn new(
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

    pub fn push(&mut self, value: T) {
        self.page_builder(value.dyn_size()).push(value);
    }

    pub fn page_builder(&mut self, size_hint: usize) -> &mut P {
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
