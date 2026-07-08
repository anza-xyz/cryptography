//! AVX-512 IFMA Ed25519 batch verification.
//!
//! This module internalizes the `ed25519-simd` verifier as an optional
//! `solana-ed25519` backend. Enable it with the `avx512` feature and build for
//! `x86_64` with `avx512f`, `avx512dq`, and `avx512ifma` target features.
//!
//! Initial import source: `efagerho/ed25519-simd-rs` at
//! `f0191ea4c5787ec5c9e6a462991398b54fa34be4`.

cfg_if::cfg_if! {
    if #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        target_feature = "avx512dq",
        target_feature = "avx512ifma",
    ))] {
        mod batch;
        mod cache;
        mod cpuid;
        mod edwards;
        mod field;
        mod hot_key_cache;
        mod policy;
        mod scalar;
        mod sha512;
        mod verifier;
        mod wide;

        pub use batch::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
        pub use cache::{CachedPublicKey, KeyCache, NullKeyCache};
        pub use hot_key_cache::HotKeyCache;
        pub use policy::VerifyPolicy;
        pub use verifier::{Verifier, VerifyInput};
    } else {
        mod unsupported;

        pub use unsupported::{
            CachedPublicKey, HotKeyCache, KeyCache, NullKeyCache, PUBLIC_KEY_LEN, SIGNATURE_LEN,
            Verifier, VerifyInput, VerifyPolicy,
        };
    }
}
