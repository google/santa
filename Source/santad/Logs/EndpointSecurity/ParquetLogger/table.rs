use crate::{column_builder::ColumnBuilder, value::Value};
use parquet2::{
    compression::CompressionOptions,
    error::Result,
    metadata::SchemaDescriptor,
    write::{DynIter, FileWriter, WriteOptions},
};
use std::io::Write;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Options {
    pub write_options: WriteOptions,
    pub compression_options: CompressionOptions,
    pub page_size: usize,
}

pub struct Table {
    columns: Vec<ColumnBuilder>,
    schema: SchemaDescriptor,
    options: Options,
}

impl Table {
    pub fn new(schema: SchemaDescriptor, options: Options) -> Self {
        let columns = schema
            .columns()
            .iter()
            .map(|column| {
                ColumnBuilder::new(
                    options.page_size,
                    column.descriptor.clone(),
                    options.compression_options,
                )
            })
            .collect::<Vec<_>>();
        Self {
            columns,
            schema,
            options,
        }
    }

    pub fn push(&mut self, column_no: usize, value: Value) -> Result<()> {
        self.columns[column_no].push(value)
    }

    pub fn push_row<'a, I>(&mut self, values: I) -> Result<()>
    where
        I: Iterator<Item = Value<'a>>,
    {
        for (column_no, value) in values.enumerate() {
            self.push(column_no, value)?;
        }
        Ok(())
    }

    pub fn push_column<'a, I>(&mut self, column_no: usize, values: I) -> Result<()>
    where
        I: Iterator<Item = Value<'a>>,
    {
        for value in values {
            self.push(column_no, value)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        match self.columns.len() {
            0 => Err(parquet2::error::Error::OutOfSpec("No columns".to_string())),
            _ => {
                let n = self.columns[0].count();
                if self.columns.iter().all(|column| column.count() == n) {
                    Ok(())
                } else {
                    Err(parquet2::error::Error::OutOfSpec(
                        "Column counts don't match".to_string(),
                    ))
                }
            }
        }
    }

    pub fn flush_to<W: Write>(&mut self, writer: &mut FileWriter<W>) -> Result<()> {
        write_row_group(writer, &mut self.columns)
    }
}

pub fn write_row_group<W: Write>(
    writer: &mut FileWriter<W>,
    columns: &mut Vec<ColumnBuilder>,
) -> Result<()> {
    let row_group = columns.iter_mut().map(|column| Ok(column.drain()));
    let row_group = DynIter::new(row_group);
    writer.write(row_group)
}
