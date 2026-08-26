//! AVX-512 IFMA Ed25519 batch verification.
//!
//! Enable it with the `avx512` feature and build for `x86_64` with `avx512f`,
//! `avx512dq`, and `avx512ifma` target features. Without those target features
//! the public API still compiles, but the [`Verifier`] constructors return an
//! [`UnsupportedError`] so the caller can fall back to another verifier.
//!
//! This is deliberately *not* one of the curve-arithmetic backends under
//! `crate::backend`: it is a self-contained Ed25519 verifier that callers
//! select explicitly, so it must stay available even when the curve backend is
//! forced to `serial` via `--cfg curve25519_backend="serial"`.
//!
//! Forked from [`ed25519-simd`] (Apache-2.0) at commit
//! `f0191ea4c5787ec5c9e6a462991398b54fa34be4`. See `ACKNOWLEDGEMENTS.md`.
//!
//! [`ed25519-simd`]: https://github.com/efagerho/ed25519-simd-rs

// Shared by both branches below, so a caller can name the error type without
// knowing which one it compiled against.
mod error;

pub use error::UnsupportedError;

cfg_if::cfg_if! {
    if #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        target_feature = "avx512dq",
        target_feature = "avx512ifma",
    ))] {
        mod batch;
        mod cache;
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
