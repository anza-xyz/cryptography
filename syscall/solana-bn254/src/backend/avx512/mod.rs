//! AVX-512 IFMA batched execution engine (8-way parallel).
//!
//! This module leverages the `vpmadd52` instructions (Integer Fused Multiply-Add)
//! introduced in AVX-512 IFMA. It is strictly gated to supported hardware
//! (e.g., AMD Zen 4 EPYC processors or Intel Ice Lake).
//!
//! # 52-Bit Architecture
//! Standard 256-bit integers are represented as four 64-bit limbs. However,
//! accumulating 64-bit multiplications natively overflows the register, forcing
//! expensive software carry-propagation logic.
//!
//! By repacking the 256-bit state into five 52-bit limbs (`5 \times 52 = 260` bits),
//! we leave 12 bits of "headroom" at the top of each 64-bit SIMD lane. This allows
//! us to natively accumulate up to `2^{12} = 4096` multiplications locally within the
//! register without ever doing a Montgomery reduction or resolving carries.
//!
//! This "lazy reduction" unlocks world-class cryptographic throughput for operations
//! like Poseidon dense matrix multiplications and Batched Multi-Miller Loops.

#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
pub mod math;
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
pub mod pack;
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
pub mod types;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
pub use types::FieldElement8x52;
