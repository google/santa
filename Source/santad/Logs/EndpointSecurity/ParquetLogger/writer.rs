use std::fs::File;

use parquet2::{
    error::{Error, Result},
    metadata::SchemaDescriptor,
    page::CompressedPage,
    write::{DynIter, DynStreamingIterator, FileWriter, WriteOptions},
};

use crate::column_builder::ColumnBuilder;

// Wraps the FileWriter for Table to allow constructing the latter from C++.
// (FileWriter is generic, but Table cannot be.)
pub enum Writer {
    Memory(FileWriter<Vec<u8>>),
    File(FileWriter<File>),
}

impl Writer {
    pub fn from_memory(schema: SchemaDescriptor, options: WriteOptions, buffer: Vec<u8>) -> Self {
        Self::Memory(FileWriter::new(buffer, schema, options, None))
    }

    pub fn from_file(schema: SchemaDescriptor, options: WriteOptions, file: File) -> Self {
        Self::File(FileWriter::new(file, schema, options, None))
    }

    pub fn open_file(schema: SchemaDescriptor, options: WriteOptions, path: &str) -> Result<Self> {
        Ok(Self::from_file(schema, options, File::create(path)?))
    }

    pub fn write<'a>(
        &mut self,
        row_group: DynIter<'a, Result<DynStreamingIterator<'a, CompressedPage, Error>>>,
    ) -> Result<()> {
        match self {
            Self::Memory(writer) => writer.write(row_group),
            Self::File(writer) => writer.write(row_group),
        }
    }
    
    pub fn end(&mut self) -> Result<u64> {
        match self {
            Self::Memory(writer) => writer.end(None),
            Self::File(writer) => writer.end(None),
        }
    }
}

pub fn write_row_group(writer: &mut Writer, columns: &mut Vec<ColumnBuilder>) -> Result<()> {
    let row_group = columns.iter_mut().map(|column| Ok(column.drain()));
    let row_group = DynIter::new(row_group);
    writer.write(row_group)
}
