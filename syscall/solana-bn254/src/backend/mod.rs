//! 256-bit Montgomery arithmetic for the BN254 scalar field (Fr).
//!
//! Handles core Montgomery arithmetic. Execution routes to either
//! pure Rust multi-limb operations or an AVX-512 IFMA batched engine,
//! selected at compile time from the active target features.

pub mod fr;
pub mod traits;
pub mod u256;

pub mod portable;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
pub mod avx512;

pub use fr::Fr;
pub use traits::{Field, MontgomeryBackend};
pub use u256::U256;

pub type Backend<F> = portable::PortableBackend<F>;
