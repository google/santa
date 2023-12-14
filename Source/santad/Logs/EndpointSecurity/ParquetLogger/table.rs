use crate::{
    column_builder::ColumnBuilder,
    value::Value,
    writer::{write_row_group, Writer},
};
use parquet2::{
    compression::{BrotliLevel, CompressionOptions},
    error::Result,
    metadata::SchemaDescriptor,
    schema::types::{ParquetType, PhysicalType},
    write::WriteOptions,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Options {
    pub write_options: WriteOptions,
    pub compression_options: CompressionOptions,
    pub page_size: usize,
}

// Wraps the API in a type that's easy to expose to C++. (Is not generic and is
// easy to construct.)
pub struct Table {
    columns: Vec<ColumnBuilder>,
    schema: SchemaDescriptor,
    options: Options,
    writer: Writer,
}

impl Table {
    pub fn new(schema: SchemaDescriptor, options: Options, writer: Writer) -> Self {
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
            writer,
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

    pub fn flush(&mut self) -> Result<()> {
        self.validate()?;
        write_row_group(&mut self.writer, &mut self.columns)
    }

    pub fn end(&mut self) -> Result<u64> {
        // TODO(adam): Flush, but only if non-empty.
        // self.flush()?;
        self.writer.end()
    }

    pub fn into_inner(self) -> (SchemaDescriptor, Writer, Options) {
        (self.schema, self.writer, self.options)
    }
}
