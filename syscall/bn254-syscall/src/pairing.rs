use {
    crate::{ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_POINT_SIZE, Endianness, G1, G2, PodG1, PodG2},
    ark_bn254::{self, Config},
    ark_ec::{bn::Bn, pairing::Pairing},
    ark_ff::{BigInteger, BigInteger256, One},
};

pub const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = ALT_BN128_G1_POINT_SIZE + ALT_BN128_G2_POINT_SIZE;
pub const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;

pub enum VersionedPairing {
    V0,
    /// SIMD-0334 - Fix alt_bn128_pairing Syscall Length Check
    V1,
}

pub fn alt_bn128_versioned_pairing(
    version: VersionedPairing,
    input: &[u8],
    endianness: Endianness,
) -> Option<Vec<u8>> {
    match version {
        VersionedPairing::V0 => {
            input.len().checked_rem(ALT_BN128_PAIRING_ELEMENT_SIZE)?;
        }
        VersionedPairing::V1 =>
        {
            #[allow(clippy::manual_is_multiple_of)]
            if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
                return None;
            }
        }
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
        Endianness::BE => result.to_bytes_be(),
        Endianness::LE => result.to_bytes_le(),
    };

    Some(output)
}
