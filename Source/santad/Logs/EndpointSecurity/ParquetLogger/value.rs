use parquet2::error::Result;

// A value can be written to a page in a column chunk in a row group in a
// parquet file in the house that Jack built.
//
// Parquet only supports a handful of physical types. In addition to what's
// listed in this enum, parquet supports int96 and fixed length arrays, which
// are not yet implemented here.
pub enum Value<'a> {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bytes(&'a [u8]),
}

impl<'a> Value<'a> {
    pub fn dyn_size(&self) -> usize {
        match self {
            Value::I32(_) => std::mem::size_of::<i32>(),
            Value::I64(_) => std::mem::size_of::<i64>(),
            Value::F32(_) => std::mem::size_of::<f32>(),
            Value::F64(_) => std::mem::size_of::<f64>(),
            Value::Bytes(b) => b.len(),
        }
    }

    pub fn as_i32(&self) -> Result<i32> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(parquet2::error::Error::InvalidParameter(
                "Expected i32".to_string(),
            )),
        }
    }

    pub fn as_i64(&self) -> Result<i64> {
        match self {
            Value::I64(v) => Ok(*v),
            _ => Err(parquet2::error::Error::InvalidParameter(
                "Expected i64".to_string(),
            )),
        }
    }

    pub fn as_f32(&self) -> Result<f32> {
        match self {
            Value::F32(v) => Ok(*v),
            _ => Err(parquet2::error::Error::InvalidParameter(
                "Expected f32".to_string(),
            )),
        }
    }

    pub fn as_f64(&self) -> Result<f64> {
        match self {
            Value::F64(v) => Ok(*v),
            _ => Err(parquet2::error::Error::InvalidParameter(
                "Expected f64".to_string(),
            )),
        }
    }

    pub fn as_bytes(&self) -> Result<&'a [u8]> {
        match self {
            Value::Bytes(v) => Ok(*v),
            _ => Err(parquet2::error::Error::InvalidParameter(
                "Expected bytes".to_string(),
            )),
        }
    }
}
