// A value can be written to a page in a column chunk in a row group in a
// parquet file in the house that Jack built.
//
// Not much is required of a value - it must have a known size and be
// async-save. The list of supported value types matches NativeType + string.
pub trait Value: PartialOrd + Send + Sync {
    // The size of this type is efficiently known.
    // This typically means fixed width or string.
    fn dyn_size(&self) -> usize;
}

impl Value for String {
    fn dyn_size(&self) -> usize {
        self.len()
    }
}

impl Value for &[u8] {
    fn dyn_size(&self) -> usize {
        self.len()
    }
}

trait Number: Sized + PartialOrd + Send + Sync {}

// These are the only numeric types supported by parquet. (There is also int96,
// but we don't worry about that.)
impl Number for i32 {}
impl Number for i64 {}
impl Number for f32 {}
impl Number for f64 {}

// NativeTypes are all values.
impl<T: Number> Value for T {
    fn dyn_size(&self) -> usize {
        std::mem::size_of::<T>()
    }
}
