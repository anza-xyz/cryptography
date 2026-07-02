use {
    crate::{Endianness, PodG1, PodG2, ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE, G1, G2},
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::One,
    bytemuck::{Pod, Zeroable},
};

/// Pair element size (192 bytes).
pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE;

/// Output size for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

/// The enum is used to version changes to the `alt_bn128_versioned_pairing` function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionedPairing {
    V0,
    /// SIMD-0334 - Fix alt_bn128_pairing Syscall Length Check
    V1,
}

/// A combined POD struct representing a (G1, G2) pairing element.
///
/// The size is exactly 192 bytes (64 bytes for G1 + 128 bytes for G2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodPair {
    pub g1: PodG1,
    pub g2: PodG2,
}

/// The output of a BN254 pairing operation as a POD type.
///
/// Logically, the result of a pairing check is just a single byte (a boolean
/// indicating success or failure). However, for historical reasons (Ethereum
/// EIP-197 compatibility), the output is padded to exactly 32 bytes.
///
/// Depending on the requested endianness, a successful pairing sets a `1` byte
/// at different ends of the array:
/// - Big-Endian (BE): The `1` is placed at the very end of the array (index 31).
/// - Little-Endian (LE): The `1` is placed at the very beginning of the array (index 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodPairingOutput(pub [u8; ALT_BN128_PAIRING_OUTPUT_SIZE]);

impl PodPairingOutput {
    /// Constructs a `PodPairingOutput` from a boolean result and the requested endianness.
    #[inline]
    pub(crate) fn from_bool(is_success: bool, endianness: Endianness) -> Self {
        let mut output = [0u8; ALT_BN128_PAIRING_OUTPUT_SIZE];
        if is_success {
            match endianness {
                Endianness::BE => output[ALT_BN128_PAIRING_OUTPUT_SIZE - 1] = 1,
                Endianness::LE => output[0] = 1,
            }
        }
        Self(output)
    }
}

/// The implementation of the `sol_alt_bn128_group_op` syscall pairing operation
/// (group operation index 0x03 for BE input/output, 0x83 for LE input/output).
///
/// **Security Note**
///
/// Full subgroup (coset) validation is performed on all provided G2 points. For G1 points,
/// because the cofactor is 1, this validation is equivalent to a standard on-curve check.
///
/// **Warning**
///
/// This is consensus-critical Agave validator code. Modifying this function can
/// result in a network fork. See the [crate-level documentation](crate) for strict
/// guidelines on SIMD approvals and versioning.
pub fn alt_bn128_versioned_pairing(
    version: VersionedPairing,
    pairs: &[PodPair],
    endianness: Endianness,
) -> Option<PodPairingOutput> {
    // reject deprecated variants
    if matches!(version, VersionedPairing::V0) {
        return None;
    }

    let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(pairs.len());

    for pair in pairs {
        let g1 = pair.g1.deserialize_affine(endianness)?;
        let g2 = pair.g2.deserialize_affine(endianness)?;
        vec_pairs.push((g1, g2));
    }

    let res = <Bn<Config> as Pairing>::multi_pairing(
        vec_pairs.iter().map(|pair| pair.0),
        vec_pairs.iter().map(|pair| pair.1),
    );

    let is_success = res.0 == ark_bn254::Fq12::one();
    Some(PodPairingOutput::from_bool(is_success, endianness))
}
