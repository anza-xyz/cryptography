use {
    crate::{Endianness, PodG1, PodG2, ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE, G1, G2},
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
};

/// Pair element size.
pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE; // 192

// Output size for pairing operation.
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

/// The version enum used to version changes to the `alt_bn128_pairing` syscall.
pub enum VersionedPairing {
    V0,
    /// SIMD-0334 - Fix alt_bn128_pairing Syscall Length Check
    V1,
}

/// The syscall implementation for the `alt_bn128_pairing` syscall.
///
/// This function is intended to be used by the Agave validator client and exists
/// primarily for validator code. Solana programs or other downstream projects
/// should use the functions from the `solana-bn254` crate in the solana-sdk instead.
///
/// # Warning
///
/// Developers should be extremely careful when modifying this function, as a
/// breaking change can result in a fork in the Solana cluster. Any such change
/// requires an approved Solana SIMD. Subsequently, a new `VersionedPairing`
/// variant must be added, and the new logic must be scoped to that variant.
pub fn alt_bn128_versioned_pairing(
    version: VersionedPairing,
    input: &[u8],
    endianness: Endianness,
) -> Option<[u8; ALT_BN128_PAIRING_OUTPUT_SIZE]> {
    // reject deprecated variants
    if matches!(version, VersionedPairing::V0) {
        return None;
    }

    #[allow(clippy::manual_is_multiple_of)]
    if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
        return None;
    }

    let chunks = input.chunks_exact(ALT_BN128_PAIRING_ELEMENT_SIZE);
    let mut vec_pairs: Vec<(G1, G2)> = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let (p_bytes, q_bytes) = chunk.split_at(ALT_BN128_G1_POINT_SIZE);

        let (g1, g2) = match endianness {
            Endianness::BE => (
                PodG1::from_be_bytes(p_bytes)?.into_affine()?,
                PodG2::from_be_bytes(q_bytes)?.into_affine()?,
            ),
            Endianness::LE => (
                PodG1::from_le_bytes(p_bytes)?.into_affine()?,
                PodG2::from_le_bytes(q_bytes)?.into_affine()?,
            ),
        };

        vec_pairs.push((g1, g2));
    }

    let res = <Bn<Config> as Pairing>::multi_pairing(
        vec_pairs.iter().map(|pair| pair.0),
        vec_pairs.iter().map(|pair| pair.1),
    );

    let result = if res.0 == ark_bn254::Fq12::one() {
        BigInteger256::from(1u64)
    } else {
        BigInteger256::from(0u64)
    };

    let output = match endianness {
        Endianness::BE => result.to_bytes_be().try_into().ok()?,
        Endianness::LE => result.to_bytes_le().try_into().ok()?,
    };

    Some(output)
}
