use std::fs::File;

use cxx::CxxString;
use parquet2::{
    compression::{BrotliLevel, CompressionOptions},
    metadata::SchemaDescriptor,
    schema::types::{ParquetType, PhysicalType},
    write::WriteOptions, error::Error,
};

use crate::{
    table::{Options, Table},
    writer::Writer,
};

#[cxx::bridge(namespace = "pedro::wire")]
mod ffi {
    // Types  supported by the C++ API.
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
        ) -> bool;
        fn table_new(args: Box<TableArgs>) -> Result<Box<Table>>;
    }
}

pub struct TableArgs {
    pub options: Options,
    pub name: String,
    pub path: String,
    pub fields: Vec<ParquetType>,
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

pub fn table_args_new(name: &CxxString, path: &CxxString) -> Box<TableArgs> {
    Box::new(TableArgs {
        options: Options {
            write_options: WriteOptions {
                write_statistics: true,
                version: parquet2::write::Version::V1,
            },
            compression_options: CompressionOptions::Brotli(Some(BrotliLevel::try_new(5).unwrap())),
            page_size: 1024,
        },
        name: name.to_string(),
        path: path.to_string(),
        fields: vec![],
    })
}

pub fn table_args_add_column(
    args: &mut TableArgs,
    name: &CxxString,
    column_type: ffi::CxxColumnType,
) -> bool {
    match cxx_column_type_to_physical_type(column_type) {
        None => false,
        Some(physical_type) => {
            args.fields
                .push(ParquetType::from_physical(name.to_string(), physical_type));
            true
        }
    }
}

pub fn table_new(args: Box<TableArgs>) -> Result<Box<Table>, Error> {
    let schema = SchemaDescriptor::new(args.name, args.fields);
    let writer = Writer::open_file(schema.clone(), args.options.write_options, &args.path)?;
    Ok(Box::new(Table::new(schema, args.options, writer)))
}
