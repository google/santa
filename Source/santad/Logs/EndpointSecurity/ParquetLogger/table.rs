use crate::{
    column_builder::ColumnBuilder,
    value::Value,
    writer::{write_row_group, Writer},
};
use parquet2::{
    compression::CompressionOptions, error::Result, metadata::SchemaDescriptor, write::WriteOptions,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Options {
    pub write_options: WriteOptions,
    pub compression_options: CompressionOptions,
    pub page_size: usize,
}

/// Wraps the API in a type that's easy to expose to C++. (Is not generic and is
/// easy to construct.)
pub struct Table {
    columns: Vec<ColumnBuilder>,
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
        Self { columns, writer }
    }

    /// Pushes a value to the column. The column number is the index the column
    /// had in the schema. The type of Value must match the type of the column
    /// as specified in new.
    ///
    /// It is not necessary to push values in order of column number. It is also
    /// not required to push one row at a time (it's fine to write column by
    /// column). However, the same number of values must be pushed to each
    /// column by the time flush is called.
    pub fn push(&mut self, column_no: usize, value: Value) -> Result<()> {
        self.columns[column_no].push(value)
    }

    /// Convenience method for pushing a row of values at a time. See push.
    pub fn push_row<'a, I>(&mut self, values: I) -> Result<()>
    where
        I: Iterator<Item = Value<'a>>,
    {
        for (column_no, value) in values.enumerate() {
            self.push(column_no, value)?;
        }
        Ok(())
    }

    /// Convenience method for pushing a column of values at a time. See push
    pub fn push_column<'a, I>(&mut self, column_no: usize, values: I) -> Result<()>
    where
        I: Iterator<Item = Value<'a>>,
    {
        for value in values {
            self.push(column_no, value)?;
        }
        Ok(())
    }

    /// Checks that the table is well-formed and returns the number of rows in
    /// the buffer.
    pub fn validate(&self) -> Result<usize> {
        match self.columns.len() {
            0 => Err(parquet2::error::Error::OutOfSpec("No columns".to_string())),
            _ => {
                let n = self.columns[0].count();
                if self.columns.iter().all(|column| column.count() == n) {
                    Ok(n)
                } else {
                    Err(parquet2::error::Error::OutOfSpec(
                        "Column counts don't match".to_string(),
                    ))
                }
            }
        }
    }

    /// Flushes a rowg group to the writer and returns the number of rows
    /// flushed. Does nothing if no rows are buffered.
    pub fn flush(&mut self) -> Result<usize> {
        match self.validate() {
            Ok(0) => Ok(0),
            Ok(n) => {
                write_row_group(&mut self.writer, &mut self.columns)?;
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }

    /// Flushes all buffered data and ends the file, writing the footer.
    pub fn end(mut self) -> Result<(u64, Writer)> {
        self.flush()?;
        let n = self.writer.end()?;
        Ok((n, self.writer))
    }

    /// Return the total buffered size of the table in bytes. This does not
    /// count bytes already written to disk, or any metadata and header and
    /// footer.
    pub fn size(&self) -> usize {
        self.columns.iter().map(|column| column.size()).sum()
    }
}
