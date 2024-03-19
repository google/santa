use crate::{page_builder::PageBuilder, value::Value};
use parquet2::{
    compression::CompressionOptions,
    error::{Error, Result},
    metadata::Descriptor,
    page::{CompressedPage, Page},
    write::{Compressor, DynIter, DynStreamingIterator},
};

/// A column is a collection of pages. It can be drained to get compressed pages
/// out. After the compressed pages are written to a file, the column chunk can
/// be reused.
pub struct ColumnBuilder {
    pages: Vec<PageBuilder>,
    page_size: usize,
    descriptor: Descriptor,
    compression_options: CompressionOptions,
}

impl ColumnBuilder {
    /// Create a new column builder. Providing invalid options will result in
    /// failures on push, not immediately.
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

    /// Compress and return the buffered pages so they can be written to a file.
    ///
    /// WARNING: due to parquet2's iterator-centric design, it's necessary to
    /// drain this iterator before calling push again. Otherwise, it's undefined
    /// which row group the newly written data will end up, and it could even be
    /// dropped.
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

    /// Append the value to the most recent page. If the page is full, create a
    /// new one.
    pub fn push(&mut self, value: Value) -> Result<()> {
        self.page_builder(value.dyn_size())?.push(value)
    }

    /// Return the most recent, partially built page. If the page can't fit the
    /// size_hint without going over page_size, a new page is created.
    ///
    /// This call can only fail if the schema is invalid.
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

    /// Returns the current size of the column in bytes, as a sum of the sizes
    /// of all buffered pages.
    pub fn size(&self) -> usize {
        self.pages.iter().map(|page| page.size()).sum()
    }

    /// Returns the current number of buffered values.
    pub fn count(&self) -> usize {
        self.pages.iter().map(|page| page.count()).sum()
    }
}
