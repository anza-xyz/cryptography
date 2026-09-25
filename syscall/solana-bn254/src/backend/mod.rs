//! 256-bit Montgomery arithmetic for the BN254 base (Fq) and scalar (Fr) fields.
//!
//! Fq uses a portable fallback or Linux x86_64 ADX/BMI2 multiplication.
//! With AVX-512 F/DQ/IFMA, independent Fq2 formula products use packed Fq lanes.
//! Poseidon uses the existing packed Fr backend.

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
