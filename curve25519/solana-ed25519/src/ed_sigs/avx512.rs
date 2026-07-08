//! Ed25519 AVX-512 IFMA batch verification.

#[cfg(target_arch = "x86_64")]
pub use crate::backend::vector::avx512::*;

#[cfg(not(target_arch = "x86_64"))]
#[path = "../backend/vector/avx512/unsupported.rs"]
mod unsupported;

#[cfg(not(target_arch = "x86_64"))]
pub use unsupported::{
    CachedPublicKey, HotKeyCache, KeyCache, NullKeyCache, PUBLIC_KEY_LEN, SIGNATURE_LEN, Verifier,
    VerifyInput, VerifyPolicy,
};
