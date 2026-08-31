pub mod util;

mod batch;
mod bip32;
mod decoding;
mod encoding;
mod heea;
mod rfc8032;
mod small_order;
mod unit_tests;

#[cfg(all(
    feature = "avx512",
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512bw",
    target_feature = "avx512dq",
    target_feature = "avx512ifma",
))]
mod avx512;
