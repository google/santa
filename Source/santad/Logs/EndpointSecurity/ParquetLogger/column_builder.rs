use crate::{page_builder::PageBuilder, value::Value};
use parquet2::{
    compression::CompressionOptions,
    error::{Error, Result},
    metadata::Descriptor,
    page::{CompressedPage, Page},
    write::{Compressor, DynIter, DynStreamingIterator},
};

// A column is a collection of pages. It can be drained to get compressed pages
// out. After the compressed pages are written to a file, the column chunk can
// be reused.
pub struct ColumnBuilder {
    pages: Vec<PageBuilder>,
    page_size: usize,
    descriptor: Descriptor,
    compression_options: CompressionOptions,
}

impl ColumnBuilder {
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
        }
    }

    pub fn drain<'a>(&'a mut self) -> DynStreamingIterator<'a, CompressedPage, Error> {
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

    pub fn push(&mut self, value: Value) -> Result<()> {
        self.page_builder(value.dyn_size())?.push(value)
    }

    pub fn page_builder(&mut self, size_hint: usize) -> Result<&mut PageBuilder> {
        let last_page = match self.pages.last_mut() {
            Some(page) => page,
            None => {
                let mut buffer = vec![];
                buffer.reserve(self.page_size);
                self.pages
                    .push(PageBuilder::new(self.descriptor.clone(), buffer)?);
                self.pages.last_mut().unwrap()
            }
        };

        if last_page.size() + size_hint > self.page_size {
            let mut buffer = vec![];
            buffer.reserve(self.page_size);
            self.pages
                .push(PageBuilder::new(self.descriptor.clone(), buffer)?);
        }

        Ok(self.pages.last_mut().unwrap())
    }
}
