//! Unified 256-bit field arithmetic for Fq (base) and Fr (scalar).
//!
//! Handles core Montgomery arithmetic. Execution routes to either
//! pure Rust multi-limb operations or highly optimized x86_64
//! assembly based on active feature flags.

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
