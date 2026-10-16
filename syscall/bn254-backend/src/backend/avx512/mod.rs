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
//!
//! Every kernel requires AVX-512 F, DQ and IFMA on the executing CPU. Crate
//! callers check `cpu::has_ifma()` before entering this module.

pub mod math;
pub mod pack;
pub mod types;

pub use types::FieldElement8x52;

pub(crate) mod fq;

/// Tests in this module skip on CPUs without IFMA. Setting `BN254_REQUIRE_IFMA`
/// turns a skip into a failure, so CI cannot silently lose coverage. They call
/// the kernels directly, so `bn254_disable` does not skip them.
#[cfg(test)]
pub(crate) fn test_cpu_supported() -> bool {
    let supported = std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512dq")
        && std::is_x86_feature_detected!("avx512ifma");
    assert!(
        supported || std::env::var_os("BN254_REQUIRE_IFMA").is_none(),
        "BN254_REQUIRE_IFMA is set, but the CPU lacks AVX-512 IFMA"
    );
    supported
}
