pub mod util;

mod batch;
mod bip32;
mod decoding;
mod encoding;
mod heea;
mod rfc8032;
#[cfg(all(
    feature = "simd",
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512dq",
    target_feature = "avx512ifma",
))]
mod simd;
mod small_order;
mod unit_tests;
