//! BN254 Scalar Field (Fr) configuration.

use super::{Field, U256};

/// BN254 Scalar Field parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Fr;

impl Field for Fr {
    const MODULUS: U256 = U256::new([
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]);
    const INV: u64 = 0xc2e1f593efffffff;
    const R2: U256 = U256::new([
        0x1bb8e645ae216da7,
        0x53fe3ab1e35c59e3,
        0x8c49833d53bb8085,
        0x0216d0b17f4e44a5,
    ]);
}
