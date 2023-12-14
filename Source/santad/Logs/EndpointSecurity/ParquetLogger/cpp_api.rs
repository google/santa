//! C++ API for the ParquetLogger. This is a thin wrapper around the Table type.

use cxx::CxxString;
use parquet2::{
    compression::{BrotliLevel, CompressionOptions},
    error::Error,
    metadata::SchemaDescriptor,
    schema::{
        types::{ParquetType, PhysicalType, PrimitiveType},
        Repetition,
    },
    write::WriteOptions,
};

use crate::{
    table::{Options, Table},
    value::Value,
    writer::Writer,
};

#[cxx::bridge(namespace = "pedro::wire")]
mod ffi {
    /// Parquet types supported by the C++ API.
    enum CxxColumnType {
        Int32,
        Int64,
        Float,
        Double,
        ByteArray,
    }

    extern "Rust" {
        type Table;
        type TableArgs;

        fn table_args_new(name: &CxxString, path: &CxxString) -> Box<TableArgs>;
        fn table_args_add_column(
            args: &mut TableArgs,
            name: &CxxString,
            physical_type: CxxColumnType,
        ) -> Result<()>;

        fn table_new(args: Box<TableArgs>) -> Result<Box<Table>>;
        fn table_push_i32(table: &mut Table, column_no: usize, value: i32) -> Result<()>;
        fn table_push_i64(table: &mut Table, column_no: usize, value: i64) -> Result<()>;
        fn table_push_f32(table: &mut Table, column_no: usize, value: f32) -> Result<()>;
        fn table_push_f64(table: &mut Table, column_no: usize, value: f64) -> Result<()>;
        fn table_push_bytes(table: &mut Table, column_no: usize, value: &[u8]) -> Result<()>;
        fn table_push_string(table: &mut Table, column_no: usize, value: &CxxString) -> Result<()>;
        fn table_flush(table: &mut Table) -> Result<usize>;
        fn table_end(table: Box<Table>) -> Result<u64>;
    }
}

/// A collection of arguments to construct a Table. Used by the C++ API for a
/// builder pattern.
struct TableArgs {
    options: Options,
    name: String,
    path: String,
    fields: Vec<ParquetType>,
}

fn cxx_column_type_to_physical_type(physical_type: ffi::CxxColumnType) -> Option<PhysicalType> {
    match physical_type {
        ffi::CxxColumnType::Int32 => Some(PhysicalType::Int32),
        ffi::CxxColumnType::Int64 => Some(PhysicalType::Int64),
        ffi::CxxColumnType::Float => Some(PhysicalType::Float),
        ffi::CxxColumnType::Double => Some(PhysicalType::Double),
        ffi::CxxColumnType::ByteArray => Some(PhysicalType::ByteArray),
        _ => None,
    }
}

fn table_args_new(name: &CxxString, path: &CxxString) -> Box<TableArgs> {
    Box::new(TableArgs {
        options: Options {
            write_options: WriteOptions {
                write_statistics: true,
                version: parquet2::write::Version::V1,
            },
            compression_options: CompressionOptions::Brotli(Some(BrotliLevel::try_new(5).unwrap())),
            // compression_options: CompressionOptions::Uncompressed,
            page_size: 1024,
        },
        name: name.to_string(),
        path: path.to_string(),
        fields: vec![],
    })
}

fn table_args_add_column(
    args: &mut TableArgs,
    name: &CxxString,
    column_type: ffi::CxxColumnType,
) -> Result<(), Error> {
    match cxx_column_type_to_physical_type(column_type) {
        None => Err(Error::InvalidParameter("invalid column type".to_string())),
        Some(physical_type) => {
            let mut field = PrimitiveType::from_physical(name.to_string(), physical_type);
            field.field_info.repetition = Repetition::Required;
            args.fields.push(ParquetType::PrimitiveType(field));
            Ok(())
        }
    }
}

fn table_new(args: Box<TableArgs>) -> Result<Box<Table>, Error> {
    let schema = SchemaDescriptor::new(args.name, args.fields);
    let writer = Writer::open_file(schema.clone(), args.options.write_options, &args.path)?;
    Ok(Box::new(Table::new(schema, args.options, writer)))
}

fn table_push_i32(table: &mut Table, column_no: usize, value: i32) -> Result<(), Error> {
    table.push(column_no, Value::I32(value))
}

fn table_push_i64(table: &mut Table, column_no: usize, value: i64) -> Result<(), Error> {
    table.push(column_no, Value::I64(value))
}

fn table_push_f32(table: &mut Table, column_no: usize, value: f32) -> Result<(), Error> {
    table.push(column_no, Value::F32(value))
}

fn table_push_f64(table: &mut Table, column_no: usize, value: f64) -> Result<(), Error> {
    table.push(column_no, Value::F64(value))
}

fn table_push_bytes(table: &mut Table, column_no: usize, value: &[u8]) -> Result<(), Error> {
    table.push(column_no, Value::Bytes(value))
}

fn table_push_string(table: &mut Table, column_no: usize, value: &CxxString) -> Result<(), Error> {
    table.push(column_no, Value::Bytes(value.as_bytes()))
}

fn table_flush(table: &mut Table) -> Result<(usize), Error> {
    table.flush()
}

fn table_end(mut table: Box<Table>) -> Result<u64, Error> {
    table.end()
}
