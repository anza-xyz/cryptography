//! 256-bit Montgomery arithmetic for the BN254 base (Fq) and scalar (Fr) fields.
//!
//! Individual elements use the portable backend. Poseidon also uses the
//! batched Fr AVX-512 IFMA backend when enabled by the target features.

pub mod fq;
pub mod fq2;
pub mod fr;
pub mod traits;
pub mod u256;

pub mod portable;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
pub mod avx512;

pub use fq::Fq;
pub use fq2::Fq2;
pub use fr::Fr;
pub use traits::{Field, MontgomeryBackend};
pub use u256::U256;

pub type Backend<F> = portable::PortableBackend<F>;
