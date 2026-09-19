//! BN254 base field (Fq) configuration for curve coordinates.

use super::{Field, U256};

/// BN254 base field parameters, with Montgomery radix `R = 2^256`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Fq;

impl Field for Fq {
    const MODULUS: U256 = U256::new([
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]);
    const INV: u64 = 0x87d20782e4866389;
    const R2: U256 = U256::new([
        0xf32cfc5b538afa89,
        0xb5e71911d44501fb,
        0x47ab1eff0a417ff6,
        0x06d89f71cab8351f,
    ]);
}
