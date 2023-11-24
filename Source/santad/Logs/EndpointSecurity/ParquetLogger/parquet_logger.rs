use parquet2::bloom_filter;

// This is a POC function that shows we can build and link Rust code.
#[no_mangle]
pub extern "C" fn parquet2_1337_bloom_filter_contains(x: i64) -> bool {
    let mut bits = vec![0; 32];
    bloom_filter::insert(&mut bits, bloom_filter::hash_native::<i64>(1337));
    bloom_filter::is_in_set(&bits, bloom_filter::hash_native(x))
}
